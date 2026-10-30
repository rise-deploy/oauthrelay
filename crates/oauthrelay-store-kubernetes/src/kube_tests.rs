//! Drives the real `kube` client against an in-memory API server to check the wire requests, the
//! mapping of status codes, and the objects the store writes.

use super::*;
use axum::{
    body::Body,
    http::{Request, Response},
};
use http_body_util::BodyExt;
use kube::Client;
use serde_json::{json, Value};
use std::{collections::BTreeMap, convert::Infallible, sync::Mutex};
use tower::service_fn;

const NAMESPACE: &str = "relay-state";
const COLLECTION: &str = "/apis/oauthrelay.dev/v1alpha1/namespaces/relay-state/transientrecords";
const START: u64 = 1_800_000_000_000;

#[derive(Default)]
struct ApiState {
    objects: BTreeMap<String, Value>,
    versions: u64,
    /// `(method, uri, body)` of every request.
    requests: Vec<(String, String, Value)>,
    /// Applies the next write but answers it with a 409, as a retry after a lost response does.
    lose_next_write_response: bool,
    /// Answers every request with this status instead.
    fail_with: Option<u16>,
}

#[derive(Clone, Default)]
struct FakeApi(Arc<Mutex<ApiState>>);

fn status(code: u16, reason: &str) -> Response<Body> {
    let body = json!({"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":reason,"reason":reason,"code":code});
    Response::builder()
        .status(code)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn ok(code: u16, body: Value) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn query(uri: &axum::http::Uri) -> BTreeMap<String, String> {
    serde_urlencoded::from_str(uri.query().unwrap_or_default()).unwrap()
}

impl FakeApi {
    fn client(&self) -> Client {
        let state = self.0.clone();
        Client::new(
            service_fn(move |request: Request<kube::client::Body>| {
                let state = state.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let bytes = body.collect().await.unwrap().to_bytes();
                    let body: Value = if bytes.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&bytes).unwrap()
                    };
                    let mut state = state.lock().unwrap();
                    state.requests.push((
                        parts.method.to_string(),
                        parts.uri.to_string(),
                        body.clone(),
                    ));
                    if let Some(code) = state.fail_with {
                        return Ok::<_, Infallible>(status(code, "InjectedFailure"));
                    }
                    let path = parts.uri.path();
                    let name = path
                        .strip_prefix(COLLECTION)
                        .unwrap_or_else(|| panic!("unexpected path {path}"))
                        .strip_prefix('/');
                    Ok(state.handle(parts.method.as_str(), name, &parts.uri, body))
                }
            }),
            NAMESPACE,
        )
    }

    fn requests(&self) -> Vec<(String, String, Value)> {
        std::mem::take(&mut self.0.lock().unwrap().requests)
    }

    fn object(&self, name: &str) -> Option<Value> {
        self.0.lock().unwrap().objects.get(name).cloned()
    }
}

impl ApiState {
    fn bump(&mut self) -> String {
        self.versions += 1;
        self.versions.to_string()
    }

    fn handle(
        &mut self,
        method: &str,
        name: Option<&str>,
        uri: &axum::http::Uri,
        mut body: Value,
    ) -> Response<Body> {
        let lose = std::mem::take(&mut self.lose_next_write_response);
        match (method, name) {
            ("GET", None) => {
                let params = query(uri);
                let selector = params.get("labelSelector");
                let (key, value) = selector
                    .and_then(|selector| selector.split_once('='))
                    .unwrap_or_default();
                let limit: usize = params
                    .get("limit")
                    .map_or(usize::MAX, |l| l.parse().unwrap());
                let matching: Vec<_> = self
                    .objects
                    .values()
                    .filter(|object| {
                        selector.is_none() || object["metadata"]["labels"][key] == value
                    })
                    .filter(|object| {
                        params.get("continue").is_none_or(|token| {
                            object["metadata"]["name"].as_str().unwrap() > token.as_str()
                        })
                    })
                    .cloned()
                    .collect();
                let items: Vec<_> = matching.iter().take(limit).cloned().collect();
                let next = (items.len() < matching.len())
                    .then(|| items.last().unwrap()["metadata"]["name"].clone());
                ok(
                    200,
                    json!({"apiVersion":"oauthrelay.dev/v1alpha1","kind":"TransientRecordList",
                        "metadata":{"resourceVersion":"1","continue":next.unwrap_or(json!(""))},"items":items}),
                )
            }
            ("GET", Some(name)) => match self.objects.get(name) {
                Some(object) => ok(200, object.clone()),
                None => status(404, "NotFound"),
            },
            ("POST", None) => {
                let name = body["metadata"]["name"].as_str().unwrap().to_owned();
                if self.objects.contains_key(&name) {
                    return status(409, "AlreadyExists");
                }
                body["metadata"]["resourceVersion"] = json!(self.bump());
                self.objects.insert(name, body.clone());
                if lose {
                    return status(409, "AlreadyExists");
                }
                ok(201, body)
            }
            ("PUT", Some(name)) => {
                let Some(current) = self.objects.get(name) else {
                    return status(404, "NotFound");
                };
                if body["metadata"]["resourceVersion"] != current["metadata"]["resourceVersion"] {
                    return status(409, "Conflict");
                }
                body["metadata"]["resourceVersion"] = json!(self.bump());
                self.objects.insert(name.to_owned(), body.clone());
                if lose {
                    return status(409, "Conflict");
                }
                ok(200, body)
            }
            ("DELETE", Some(name)) => {
                let Some(current) = self.objects.get(name) else {
                    return status(404, "NotFound");
                };
                let precondition = &body["preconditions"]["resourceVersion"];
                if !precondition.is_null()
                    && *precondition != current["metadata"]["resourceVersion"]
                {
                    return status(409, "Conflict");
                }
                self.objects.remove(name);
                ok(
                    200,
                    json!({"kind":"Status","apiVersion":"v1","metadata":{},"status":"Success"}),
                )
            }
            other => panic!("unexpected request {other:?}"),
        }
    }
}

fn kube_store(api: &FakeApi) -> (Arc<KubeClient>, KubernetesStore<KubeClient>) {
    let client = Arc::new(KubeClient::new(
        api.client(),
        NAMESPACE,
        RecordMapping::TransientRecord,
    ));
    let store = KubernetesStore::with_clock(client.clone(), Arc::new(|| START));
    (client, store)
}

const TTL: Duration = Duration::from_secs(300);

#[tokio::test]
async fn transient_record_objects_have_the_documented_shape() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    assert!(store
        .put_if_absent("replay:code:abc", &[0, 1, 2, 255], TTL)
        .await
        .unwrap());
    let object = api.object(&object_name("replay:code:abc")).unwrap();
    assert_eq!(object["apiVersion"], "oauthrelay.dev/v1alpha1");
    assert_eq!(object["kind"], "TransientRecord");
    assert_eq!(object["metadata"]["namespace"], NAMESPACE);
    assert_eq!(
        object["metadata"]["labels"],
        json!({"app.kubernetes.io/managed-by":"oauthrelay","oauthrelay.dev/purpose":"replay"})
    );
    assert_eq!(
        object["spec"],
        json!({
            "key": "replay:code:abc",
            "value": "AAEC/w==",
            // 2027-01-15T08:00:00Z plus the TTL.
            "expiresAt": "2027-01-15T08:05:00.000Z",
        })
    );
    // The object deserializes as the typed resource the CRD describes.
    let typed: TransientRecord = serde_json::from_value(object).unwrap();
    assert_eq!(typed.spec.key, "replay:code:abc");
}

#[test]
fn timestamps_round_trip_at_millisecond_precision() {
    use crate::mapping::{format_time, parse_time};
    assert_eq!(format_time(0).unwrap(), "1970-01-01T00:00:00.000Z");
    assert_eq!(
        format_time(START + 1234).unwrap(),
        "2027-01-15T08:00:01.234Z"
    );
    for millis in [0, 1, START, START + 999, mapping::max_expiry_millis()] {
        assert_eq!(parse_time(&format_time(millis).unwrap()).unwrap(), millis);
    }
    assert!(format_time(mapping::max_expiry_millis() + 1).is_err());
    // Any RFC 3339 offset and fraction length parses.
    assert_eq!(
        parse_time("2027-01-15T10:00:01.234567890+02:00").unwrap(),
        START + 1234
    );
    assert_eq!(parse_time("2027-01-15T08:00:00Z").unwrap(), START);
    assert_eq!(parse_time("1969-12-31T23:59:59Z").unwrap(), 0);
    for bad in ["", "tomorrow", "2027-01-15 08:00:00", "2027-01-15T08:00:00"] {
        assert!(parse_time(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn requests_use_the_resource_path_conditions_and_selector() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    let name = object_name("refresh:handle:a");
    assert!(store
        .put_if_absent("refresh:handle:a", b"one", TTL)
        .await
        .unwrap());
    assert_eq!(
        store.get("refresh:handle:a").await.unwrap().unwrap().value,
        b"one"
    );
    assert!(store
        .compare_and_swap("refresh:handle:a", b"one", b"two", TTL)
        .await
        .unwrap());
    store.sweep().await.unwrap();
    store.delete("refresh:handle:a").await.unwrap();

    let requests = api.requests();
    let summary: Vec<_> = requests
        .iter()
        .map(|(method, uri, _)| {
            let uri: axum::http::Uri = uri.parse().unwrap();
            (
                method.as_str().to_owned(),
                uri.path().to_owned(),
                query(&uri),
            )
        })
        .collect();
    let item = format!("{COLLECTION}/{name}");
    let no_query = BTreeMap::new();
    let selection = BTreeMap::from([
        (
            "labelSelector".to_owned(),
            "app.kubernetes.io/managed-by=oauthrelay".to_owned(),
        ),
        ("limit".to_owned(), "500".to_owned()),
    ]);
    assert_eq!(
        summary,
        vec![
            ("POST".to_owned(), COLLECTION.to_owned(), no_query.clone()),
            ("GET".to_owned(), item.clone(), no_query.clone()),
            ("GET".to_owned(), item.clone(), no_query.clone()),
            ("PUT".to_owned(), item.clone(), no_query.clone()),
            ("GET".to_owned(), COLLECTION.to_owned(), selection),
            ("DELETE".to_owned(), item, no_query),
        ]
    );
    // The first POST carried no resourceVersion; the PUT carried the version it read.
    assert!(requests[0].2["metadata"]["resourceVersion"].is_null());
    assert_eq!(requests[3].2["metadata"]["resourceVersion"], "1");
    // An unconditional delete sends no precondition.
    assert!(requests[5].2["preconditions"].is_null());
}

#[tokio::test]
async fn sweeping_sends_a_resource_version_precondition_and_skips_changed_objects() {
    let api = FakeApi::default();
    let (client, store) = kube_store(&api);
    assert!(store
        .put_if_absent("replay:code:a", b"1", Duration::from_millis(1))
        .await
        .unwrap());
    let later = KubernetesStore::with_clock(client.clone(), Arc::new(|| START + 10));
    api.requests();
    assert_eq!(
        later.sweep().await.unwrap(),
        SweepReport {
            listed: 1,
            deleted: 1,
            skipped: 0
        }
    );
    let requests = api.requests();
    let delete = requests
        .iter()
        .find(|(method, ..)| method == "DELETE")
        .unwrap();
    assert_eq!(delete.2["preconditions"]["resourceVersion"], "1");
    assert!(api.object(&object_name("replay:code:a")).is_none());

    // A stale precondition is a 409, which the sweeper treats as "renewed".
    assert_eq!(
        client
            .delete(&object_name("replay:code:a"), Some("1"))
            .await
            .unwrap(),
        DeleteOutcome::NotFound
    );
    assert!(store
        .put_if_absent("replay:code:a", b"2", TTL)
        .await
        .unwrap());
    assert_eq!(
        client
            .delete(&object_name("replay:code:a"), Some("1"))
            .await
            .unwrap(),
        DeleteOutcome::Conflict
    );
}

#[tokio::test]
async fn sweeping_follows_continue_tokens() {
    let api = FakeApi::default();
    let (client, store) = kube_store(&api);
    for index in 0..3 {
        assert!(store
            .put_if_absent(&format!("replay:{index}"), b"1", Duration::from_millis(1))
            .await
            .unwrap());
    }
    let page = client.list(MANAGED_SELECTOR, 2, None).await.unwrap();
    assert_eq!(page.items.len(), 2);
    let token = page.continue_token.unwrap();
    let rest = client
        .list(MANAGED_SELECTOR, 2, Some(&token))
        .await
        .unwrap();
    assert_eq!(rest.items.len(), 1);
    assert_eq!(rest.continue_token, None);
}

#[tokio::test]
async fn lists_select_only_managed_objects_and_skip_undecodable_ones() {
    let api = FakeApi::default();
    let (client, store) = kube_store(&api);
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    {
        let mut state = api.0.lock().unwrap();
        // A foreign object without the label, and a labelled one that is not a valid record.
        state.objects.insert(
            "foreign".into(),
            json!({"metadata":{"name":"foreign","resourceVersion":"50"},"spec":{}}),
        );
        state.objects.insert(
            "oauthrelay-broken".into(),
            json!({"metadata":{"name":"oauthrelay-broken","resourceVersion":"51",
                "labels":{"app.kubernetes.io/managed-by":"oauthrelay"}},"spec":{"key":"k"}}),
        );
    }
    let page = client.list(MANAGED_SELECTOR, 500, None).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.undecodable, vec!["oauthrelay-broken".to_owned()]);
    // The sweeper neither deletes the foreign object nor chokes on the broken one.
    let later = KubernetesStore::with_clock(client.clone(), Arc::new(|| START + 10 * 60_000));
    assert_eq!(later.sweep().await.unwrap().deleted, 1);
    assert!(api.object("foreign").is_some());
    assert!(api.object("oauthrelay-broken").is_some());
}

#[tokio::test]
async fn a_malformed_object_under_a_records_name_is_an_error_not_an_absence() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    api.0.lock().unwrap().objects.insert(
        object_name("replay:a"),
        json!({"metadata":{"name":object_name("replay:a"),"resourceVersion":"7"},"spec":{"key":"replay:a","value":"!!","expiresAt":"2030-01-01T00:00:00Z"}}),
    );
    assert!(matches!(
        store.get("replay:a").await,
        Err(StoreError::Backend(_))
    ));
    assert!(matches!(
        store.put_if_absent("replay:a", b"1", TTL).await,
        Err(StoreError::Backend(_))
    ));
}

#[tokio::test]
async fn status_codes_map_to_outcomes_and_other_failures_are_errors() {
    let api = FakeApi::default();
    let (client, _) = kube_store(&api);
    let record = NewRecord {
        name: "oauthrelay-x",
        key: "replay:x",
        value: b"1",
        expires_at_ms: START,
    };
    assert_eq!(client.get("oauthrelay-x").await.unwrap(), None);
    assert_eq!(
        client.replace(record, "1").await.unwrap(),
        ReplaceOutcome::NotFound
    );
    assert_eq!(
        client.delete("oauthrelay-x", None).await.unwrap(),
        DeleteOutcome::NotFound
    );
    assert_eq!(client.create(record).await.unwrap(), CreateOutcome::Created);
    assert_eq!(
        client.create(record).await.unwrap(),
        CreateOutcome::AlreadyExists
    );
    assert_eq!(
        client.replace(record, "stale").await.unwrap(),
        ReplaceOutcome::Conflict
    );
    assert_eq!(
        client.replace(record, "1").await.unwrap(),
        ReplaceOutcome::Replaced
    );

    for code in [403, 500, 503] {
        api.0.lock().unwrap().fail_with = Some(code);
        assert!(client.get("oauthrelay-x").await.is_err(), "{code}");
        assert!(client.create(record).await.is_err(), "{code}");
        assert!(client.replace(record, "1").await.is_err(), "{code}");
        assert!(client.delete("oauthrelay-x", None).await.is_err(), "{code}");
        assert!(
            client.list(MANAGED_SELECTOR, 1, None).await.is_err(),
            "{code}"
        );
    }
}

#[tokio::test]
async fn probe_reports_a_forbidden_list() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    store.probe().await.unwrap();
    api.0.lock().unwrap().fail_with = Some(403);
    let error = format!("{:#}", store.probe().await.unwrap_err());
    assert!(
        error.contains("transientrecords.oauthrelay.dev in namespace \"relay-state\""),
        "{error}"
    );
    assert!(
        error.contains("grant get, list, create, update and delete"),
        "{error}"
    );
}

#[tokio::test]
async fn a_lost_response_is_resolved_end_to_end() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    api.0.lock().unwrap().lose_next_write_response = true;
    assert!(store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    api.0.lock().unwrap().lose_next_write_response = true;
    assert!(store
        .compare_and_swap("replay:a", b"mine", b"mine2", TTL)
        .await
        .unwrap());
    assert_eq!(
        store.get("replay:a").await.unwrap().unwrap().value,
        b"mine2"
    );
    assert!(!store
        .put_if_absent("replay:a", b"other", TTL)
        .await
        .unwrap());
}

#[tokio::test]
async fn concurrent_puts_and_swaps_have_exactly_one_winner() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    let store = Arc::new(store);
    let mut tasks = Vec::new();
    for index in 0..20 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put_if_absent("replay:a", format!("writer-{index}").as_bytes(), TTL)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);

    assert!(store
        .put_if_absent("refresh:a", b"start", TTL)
        .await
        .unwrap());
    let mut tasks = Vec::new();
    for index in 0..20 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .compare_and_swap(
                    "refresh:a",
                    b"start",
                    format!("writer-{index}").as_bytes(),
                    TTL,
                )
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
}

#[test]
fn the_crd_bundle_describes_the_namespaced_resource() {
    let yaml = crds_yaml().unwrap();
    let crd: Value = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(crd["metadata"]["name"], "transientrecords.oauthrelay.dev");
    assert_eq!(crd["spec"]["scope"], "Namespaced");
    let version = &crd["spec"]["versions"][0];
    assert_eq!(version["name"], "v1alpha1");
    let spec = &version["schema"]["openAPIV3Schema"]["properties"]["spec"];
    assert_eq!(spec["required"], json!(["expiresAt", "key", "value"]));
    assert_eq!(spec["properties"]["expiresAt"]["format"], "date-time");
    assert_eq!(spec["properties"]["key"]["maxLength"], 1024);
    assert_eq!(spec["properties"]["key"]["minLength"], 1);
    assert!(
        !yaml.contains("crate::"),
        "rustdoc links must not leak into the CRD"
    );
    // The resource name `RecordMapping` reports is the one the CRD installs.
    assert_eq!(
        RecordMapping::TransientRecord.resource_name(),
        crd["metadata"]["name"]
    );
    assert_eq!(
        RecordMapping::from_resource_name("transientrecords.oauthrelay.dev"),
        Some(RecordMapping::TransientRecord)
    );
    assert_eq!(
        RecordMapping::from_resource_name("relays.oauthrelay.dev"),
        None
    );
}
