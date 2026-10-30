//! Drives the real `kube` client against an in-memory API server to check the wire requests, the
//! mapping of status codes, and the objects the store writes.

use super::*;
use axum::{
    body::Body,
    http::{Request, Response},
};
use http_body_util::BodyExt;
use kube::{api::DynamicObject, Client};
use serde_json::{json, Value};
use std::{collections::BTreeMap, convert::Infallible, sync::Mutex};
use tower::service_fn;

const NAMESPACE: &str = "relay-state";
const COLLECTION: &str = "/apis/oauthrelay.dev/v1alpha1/namespaces/relay-state/transientrecords";
const DEX_COLLECTION: &str = "/apis/dex.coreos.com/v1/namespaces/relay-state/authcodes";
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
    /// Answers every request on the resource as the API server does when the resource type is
    /// not served, for instance because its CRD was removed.
    missing_type: Option<MissingType>,
    /// Verbs the access review denies.
    denied_verbs: Vec<String>,
}

#[derive(Clone, Copy)]
enum MissingType {
    /// The API server's own 404 `Status`.
    Status,
    /// A 404 whose body is not a `Status`, as from a proxy in front of the API server.
    PlainText,
}

#[derive(Clone)]
struct FakeApi {
    state: Arc<Mutex<ApiState>>,
    collection: &'static str,
}

fn status(code: u16, reason: &str) -> Response<Body> {
    let body = json!({"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":reason,"reason":reason,"code":code});
    Response::builder()
        .status(code)
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// The 404 for an object that does not exist, as the API server writes it: `details` names the
/// object, its group and its resource.
fn not_found(name: &str) -> Response<Body> {
    let body = json!({"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure",
        "message":format!("transientrecords.oauthrelay.dev \"{name}\" not found"),
        "reason":"NotFound",
        "details":{"name":name,"group":"oauthrelay.dev","kind":"transientrecords"},"code":404});
    Response::builder()
        .status(404)
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// The 404 for a resource type that is not served: the generic not-found handler's `Status`,
/// which names no object.
fn type_not_found() -> Response<Body> {
    let body = json!({"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure",
        "message":"the server could not find the requested resource","reason":"NotFound",
        "details":{},"code":404});
    Response::builder()
        .status(404)
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

impl Default for FakeApi {
    fn default() -> Self {
        Self::serving(COLLECTION)
    }
}

impl FakeApi {
    fn serving(collection: &'static str) -> Self {
        Self {
            state: Arc::default(),
            collection,
        }
    }

    fn client(&self) -> Client {
        let state = self.state.clone();
        let collection = self.collection;
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
                    if path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
                        let verb = body["spec"]["resourceAttributes"]["verb"].as_str().unwrap();
                        assert_eq!(body["spec"]["resourceAttributes"]["namespace"], NAMESPACE);
                        assert_eq!(
                            body["spec"]["resourceAttributes"]["resource"],
                            collection.rsplit('/').next().unwrap()
                        );
                        let allowed = !state.denied_verbs.iter().any(|denied| denied == verb);
                        let mut review = body.clone();
                        review["status"] = json!({"allowed": allowed});
                        return Ok(ok(201, review));
                    }
                    match state.missing_type {
                        Some(MissingType::Status) => return Ok(type_not_found()),
                        Some(MissingType::PlainText) => {
                            return Ok(Response::builder()
                                .status(404)
                                .body(Body::from("404 page not found\n"))
                                .unwrap())
                        }
                        None => {}
                    }
                    let name = path
                        .strip_prefix(collection)
                        .unwrap_or_else(|| panic!("unexpected path {path}"))
                        .strip_prefix('/');
                    Ok(state.handle(parts.method.as_str(), name, &parts.uri, body))
                }
            }),
            NAMESPACE,
        )
    }

    fn requests(&self) -> Vec<(String, String, Value)> {
        std::mem::take(&mut self.state.lock().unwrap().requests)
    }

    fn object(&self, name: &str) -> Option<Value> {
        self.state.lock().unwrap().objects.get(name).cloned()
    }
}

/// Evaluates a label selector of comma-separated `key=value` and `key in (a,b)` terms.
fn selector_matches(selector: &str, object: &Value) -> bool {
    let mut terms = Vec::new();
    let (mut depth, mut start) = (0, 0);
    for (index, character) in selector.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                terms.push(&selector[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    terms.push(&selector[start..]);
    terms.into_iter().all(|term| {
        let labels = &object["metadata"]["labels"];
        if let Some((key, values)) = term.split_once(" in (") {
            let values = values.strip_suffix(')').unwrap();
            labels[key]
                .as_str()
                .is_some_and(|label| values.split(',').any(|value| value == label))
        } else {
            let (key, value) = term.split_once('=').unwrap();
            labels[key] == value
        }
    })
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
                let limit: usize = params
                    .get("limit")
                    .map_or(usize::MAX, |l| l.parse().unwrap());
                let matching: Vec<_> = self
                    .objects
                    .values()
                    .filter(|object| {
                        selector.is_none_or(|selector| selector_matches(selector, object))
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
                None => not_found(name),
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
                    return not_found(name);
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
                    return not_found(name);
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
    kube_store_for(api, RecordMapping::TransientRecord)
}

fn kube_store_for(
    api: &FakeApi,
    mapping: RecordMapping,
) -> (Arc<KubeClient>, KubernetesStore<KubeClient>) {
    let client = Arc::new(KubeClient::new(api.client(), NAMESPACE, mapping));
    let store = KubernetesStore::with_clock(client.clone(), Arc::new(|| START));
    (client, store)
}

fn dex_api() -> FakeApi {
    FakeApi::serving(DEX_COLLECTION)
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
        json!({"app.kubernetes.io/managed-by":"oauthrelay","oauthrelay.dev/purpose":"replay",
            // START is the first instant of unix hour 500000, and the record lives 5 minutes.
            "oauthrelay.dev/expires-hour":"500000"})
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
    let later = KubernetesStore::with_clock(client.clone(), Arc::new(|| START + 40_000));
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
        let mut state = api.state.lock().unwrap();
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
    api.state.lock().unwrap().objects.insert(
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
        api.state.lock().unwrap().fail_with = Some(code);
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
    api.state.lock().unwrap().fail_with = Some(403);
    let error = format!("{:#}", store.probe().await.unwrap_err());
    assert!(
        error.contains("transientrecords.oauthrelay.dev in namespace \"relay-state\""),
        "{error}"
    );
    assert!(
        error.contains("the CRD is installed (`oauthrelay crds`)"),
        "{error}"
    );
    assert!(
        error.contains("grants get, list, create, update, delete"),
        "{error}"
    );
}

#[tokio::test]
async fn probe_reviews_each_verb_in_the_namespace_and_names_the_missing_ones() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    store.probe().await.unwrap();
    let reviews: Vec<_> = api
        .requests()
        .into_iter()
        .filter(|(method, uri, _)| method == "POST" && uri.contains("selfsubjectaccessreviews"))
        .map(|(_, _, body)| {
            let attributes = &body["spec"]["resourceAttributes"];
            (
                attributes["verb"].as_str().unwrap().to_owned(),
                attributes["group"].as_str().unwrap().to_owned(),
                attributes["resource"].as_str().unwrap().to_owned(),
                attributes["namespace"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected: Vec<_> = ["get", "list", "create", "update", "delete"]
        .map(|verb| {
            (
                verb.to_owned(),
                "oauthrelay.dev".to_owned(),
                "transientrecords".to_owned(),
                NAMESPACE.to_owned(),
            )
        })
        .into();
    assert_eq!(reviews, expected);

    api.state.lock().unwrap().denied_verbs = vec!["create".into(), "update".into()];
    let error = format!("{:#}", store.probe().await.unwrap_err());
    assert!(
        error.contains("lacks create, update on transientrecords.oauthrelay.dev"),
        "{error}"
    );
    // A review the API server refuses to evaluate fails startup too.
    api.state.lock().unwrap().denied_verbs.clear();
    {
        let (client, _) = kube_store(&api);
        api.state.lock().unwrap().fail_with = Some(500);
        let error = format!("{:#}", client.permits("get").await.unwrap_err());
        assert!(error.contains("SelfSubjectAccessReview"), "{error}");
    }
}

#[tokio::test]
async fn a_resource_type_that_is_not_served_is_an_error_not_an_absence() {
    let record = NewRecord {
        name: "oauthrelay-x",
        key: "replay:x",
        value: b"1",
        expires_at_ms: START,
    };
    for missing in [MissingType::Status, MissingType::PlainText] {
        let api = FakeApi::default();
        let (client, store) = kube_store(&api);
        api.state.lock().unwrap().missing_type = Some(missing);
        assert!(client.get("oauthrelay-x").await.is_err());
        assert!(client.replace(record, "1").await.is_err());
        assert!(client.delete("oauthrelay-x", None).await.is_err());
        assert!(client.delete("oauthrelay-x", Some("1")).await.is_err());
        assert!(client.create(record).await.is_err());
        assert!(client.list(MANAGED_SELECTOR, 1, None).await.is_err());
        assert!(matches!(
            store.get("replay:x").await,
            Err(StoreError::Backend(_))
        ));
        assert!(matches!(
            store.compare_and_swap("replay:x", b"1", b"2", TTL).await,
            Err(StoreError::Backend(_))
        ));
        assert!(matches!(
            store.delete("replay:x").await,
            Err(StoreError::Backend(_))
        ));
        assert!(store.probe().await.is_err());
    }
}

#[test]
fn only_a_status_naming_the_object_is_a_missing_object() {
    use kube::core::{response::StatusDetails, Status};
    let status = |code, reason: &str, name: &str| Status {
        code,
        reason: reason.into(),
        details: (!name.is_empty()).then(|| StatusDetails {
            name: name.into(),
            group: String::new(),
            kind: String::new(),
            uid: String::new(),
            causes: Vec::new(),
            retry_after_seconds: 0,
        }),
        ..Status::default()
    };
    use crate::kube_client::is_object_not_found as missing;
    assert!(missing(&status(404, "NotFound", "obj"), "obj"));
    // Another object's name, no details, another reason or another code.
    assert!(!missing(&status(404, "NotFound", "other"), "obj"));
    assert!(!missing(&status(404, "NotFound", ""), "obj"));
    assert!(!missing(
        &status(404, "Failed to parse error data", ""),
        "obj"
    ));
    assert!(!missing(&status(404, "", "obj"), "obj"));
    assert!(!missing(&status(403, "NotFound", "obj"), "obj"));
}

#[tokio::test]
async fn a_lost_response_is_resolved_end_to_end() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    api.state.lock().unwrap().lose_next_write_response = true;
    assert!(store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    api.state.lock().unwrap().lose_next_write_response = true;
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

#[tokio::test]
async fn dex_auth_codes_have_the_shape_dex_expects_and_can_never_be_exchanged() {
    let api = dex_api();
    let (_, store) = kube_store_for(&api, RecordMapping::DexAuthCode);
    assert!(store
        .put_if_absent("replay:code:abc", &[0, 1, 2, 255], TTL)
        .await
        .unwrap());
    let name = RecordMapping::DexAuthCode.object_name("replay:code:abc");
    assert!(
        name.starts_with("zzzzzzzzzzz") && name.len() == 63,
        "{name}"
    );
    let object = api.object(&name).unwrap();
    assert_eq!(object["apiVersion"], "dex.coreos.com/v1");
    assert_eq!(object["kind"], "AuthCode");
    assert_eq!(object["metadata"]["namespace"], NAMESPACE);
    assert_eq!(
        object["metadata"]["labels"],
        json!({"app.kubernetes.io/managed-by":"oauthrelay","oauthrelay.dev/purpose":"replay",
            // START is the first instant of unix hour 500000, and the record lives 5 minutes.
            "oauthrelay.dev/expires-hour":"500000"})
    );
    // Exactly the fields of Dex's AuthCode that carry the record, and nothing else: no claims
    // and no scopes, and none of the unused string fields.
    let fields: std::collections::BTreeSet<_> = object
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        [
            "apiVersion",
            "clientID",
            "code_challenge",
            "code_challenge_method",
            "connectorData",
            "connectorID",
            "expiry",
            "kind",
            "metadata",
            "redirectURI",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(object["connectorData"], "AAEC/w==");
    assert_eq!(object["expiry"], "2027-01-15T08:05:00.000Z");
    assert_eq!(object["connectorID"], "oauthrelay");
    // The client ID is not a Dex client, so `authCode.ClientID != client.ID` rejects the code
    // for every real client; the redirect URI is not a URL a client could register either.
    assert_eq!(object["clientID"], "oauthrelay:transient-record");
    assert_eq!(object["redirectURI"], "urn:oauthrelay:transient-record");
    // A random S256 challenge: 43 base64url characters, different for every write.
    let challenge = object["code_challenge"].as_str().unwrap();
    assert_eq!(object["code_challenge_method"], "S256");
    assert_eq!(challenge.len(), 43);
    assert!(challenge
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    let another = RecordMapping::DexAuthCode
        .encode(
            NAMESPACE,
            &NewRecord {
                name: "n",
                key: "replay:code:abc",
                value: b"x",
                expires_at_ms: START,
            },
        )
        .unwrap();
    assert_ne!(another.data["code_challenge"], object["code_challenge"]);
}

#[test]
fn dex_connector_data_is_padded_standard_base64_for_every_length() {
    // Go's encoding/json decodes []byte only from padded standard base64; anything else makes
    // Dex fail to list its authcodes.
    for length in 0..=7 {
        let value = vec![0xfb_u8; length];
        let object = RecordMapping::DexAuthCode
            .encode(
                NAMESPACE,
                &NewRecord {
                    name: "n",
                    key: "k",
                    value: &value,
                    expires_at_ms: START,
                },
            )
            .unwrap();
        let encoded = object.data["connectorData"].as_str().unwrap();
        assert_eq!(encoded.len() % 4, 0, "{length}");
        assert!(
            encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')),
            "{encoded}"
        );
    }
}

#[tokio::test]
async fn dex_objects_work_end_to_end_like_the_default_mapping() {
    let api = dex_api();
    let (client, store) = kube_store_for(&api, RecordMapping::DexAuthCode);
    let store = Arc::new(store);
    // A lost response on create and on replace.
    api.state.lock().unwrap().lose_next_write_response = true;
    assert!(store.put_if_absent("refresh:a", b"one", TTL).await.unwrap());
    api.state.lock().unwrap().lose_next_write_response = true;
    assert!(store
        .compare_and_swap("refresh:a", b"one", b"two", TTL)
        .await
        .unwrap());
    assert_eq!(store.get("refresh:a").await.unwrap().unwrap().value, b"two");
    assert!(!store
        .put_if_absent("refresh:a", b"other", TTL)
        .await
        .unwrap());

    // Concurrency.
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

    // Expired records are taken over, and swept with a version precondition, but a code that
    // Dex itself wrote (no managed-by label) is never listed or touched.
    api.state.lock().unwrap().objects.insert(
        "dex-own-code".into(),
        json!({"apiVersion":"dex.coreos.com/v1","kind":"AuthCode",
            "metadata":{"name":"dex-own-code","resourceVersion":"900"},
            "clientID":"app","connectorData":"c2VjcmV0","expiry":"2001-01-01T00:00:00Z"}),
    );
    let later = KubernetesStore::with_clock(client.clone(), Arc::new(|| START + 10 * 60_000));
    api.requests();
    assert_eq!(
        later.sweep().await.unwrap(),
        SweepReport {
            listed: 2,
            deleted: 2,
            skipped: 0
        }
    );
    assert!(api.object("dex-own-code").is_some());
    let requests = api.requests();
    let list = requests
        .iter()
        .find(|(method, ..)| method == "GET")
        .unwrap();
    assert!(list
        .1
        .contains("labelSelector=app.kubernetes.io%2Fmanaged-by%3Doauthrelay"));
    assert!(requests
        .iter()
        .filter(|(method, ..)| method == "DELETE")
        .all(|(.., body)| !body["preconditions"]["resourceVersion"].is_null()));
}

#[test]
fn dex_decoding_rejects_malformed_codes() {
    let decode = |data: Value| {
        let object: DynamicObject = serde_json::from_value(json!({
            "metadata": {"name": "n", "resourceVersion": "1"},
            "connectorData": data["connectorData"], "expiry": data["expiry"],
        }))
        .unwrap();
        RecordMapping::DexAuthCode.decode(&object)
    };
    let stored =
        decode(json!({"connectorData":"AAEC/w==","expiry":"2027-01-15T08:00:01.234Z"})).unwrap();
    assert_eq!(stored.value, [0, 1, 2, 255]);
    assert_eq!(stored.expires_at_ms, START + 1234);
    assert!(decode(json!({"connectorData":"!!","expiry":"2027-01-15T08:00:00Z"})).is_err());
    assert!(decode(json!({"connectorData":"AA==","expiry":"soon"})).is_err());
    assert!(decode(json!({"expiry":"2027-01-15T08:00:00Z"})).is_err());
    assert!(decode(json!({"connectorData":"AA=="})).is_err());
}

#[test]
fn resource_names_select_the_mapping() {
    for mapping in [RecordMapping::TransientRecord, RecordMapping::DexAuthCode] {
        assert_eq!(
            RecordMapping::from_resource_name(mapping.resource_name()),
            Some(mapping)
        );
        let resource = mapping.api_resource();
        assert_eq!(
            mapping.resource_name(),
            format!("{}.{}", resource.plural, resource.group)
        );
    }
    let dex = RecordMapping::DexAuthCode.api_resource();
    assert_eq!(
        (
            dex.group.as_str(),
            dex.version.as_str(),
            dex.kind.as_str(),
            dex.plural.as_str()
        ),
        ("dex.coreos.com", "v1", "AuthCode", "authcodes")
    );
    assert_eq!(dex.api_version, "dex.coreos.com/v1");
}

#[tokio::test]
async fn every_write_rewrites_the_expiry_hour_label() {
    let api = FakeApi::default();
    let (_, store) = kube_store(&api);
    let name = object_name("refresh:a");
    let hour = |api: &FakeApi| {
        api.object(&name).unwrap()["metadata"]["labels"]["oauthrelay.dev/expires-hour"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert!(store
        .put_if_absent("refresh:a", b"1", Duration::from_secs(60))
        .await
        .unwrap());
    assert_eq!(hour(&api), "500000");
    // A swap restarts the TTL, so it moves the record to the later bucket.
    assert!(store
        .compare_and_swap("refresh:a", b"1", b"2", Duration::from_secs(2 * 3600))
        .await
        .unwrap());
    assert_eq!(hour(&api), "500002");
    // So does taking over an expired record.
    let later = KubernetesStore::with_clock(
        Arc::new(KubeClient::new(
            api.client(),
            NAMESPACE,
            RecordMapping::TransientRecord,
        )),
        Arc::new(|| START + 3 * EXPIRY_BUCKET_MS),
    );
    assert!(later
        .put_if_absent("refresh:a", b"3", Duration::from_secs(3600))
        .await
        .unwrap());
    assert_eq!(hour(&api), "500004");
}

#[tokio::test]
async fn bucket_sweeps_send_the_expiry_selector_and_delete_with_a_precondition() {
    let api = FakeApi::default();
    let (client, _) = kube_store(&api);
    let now = Arc::new(std::sync::atomic::AtomicU64::new(START + 600_000));
    let source = now.clone();
    let store = KubernetesStore::with_clock(
        client.clone(),
        Arc::new(move || source.load(std::sync::atomic::Ordering::SeqCst)),
    );
    assert!(store
        .put_if_absent("replay:soon", b"1", Duration::from_secs(60))
        .await
        .unwrap());
    assert!(store
        .put_if_absent("replay:later", b"1", Duration::from_secs(3 * 3600))
        .await
        .unwrap());
    // A legacy record: managed, but without the hour label.
    api.state.lock().unwrap().objects.insert(
        "oauthrelay-legacy".into(),
        json!({"metadata":{"name":"oauthrelay-legacy","resourceVersion":"70",
            "labels":{"app.kubernetes.io/managed-by":"oauthrelay"}},
            "spec":{"key":"replay:legacy","value":"AQ==","expiresAt":"2001-01-01T00:00:00Z"}}),
    );
    api.requests();
    // The first sweep is a full pass: it finds the legacy record too.
    assert_eq!(store.inner.sweep_tick().await.unwrap().deleted, 1);
    assert!(api.object("oauthrelay-legacy").is_none());
    // The next lists hour 500000 only.
    now.store(
        START + 600_000 + 90_000,
        std::sync::atomic::Ordering::SeqCst,
    );
    api.requests();
    let report = store.inner.sweep_tick().await.unwrap();
    assert_eq!((report.listed, report.deleted), (1, 1));
    assert!(api.object(&object_name("replay:soon")).is_none());
    assert!(api.object(&object_name("replay:later")).is_some());
    let requests = api.requests();
    let list = requests
        .iter()
        .find(|(method, ..)| method == "GET")
        .unwrap();
    let uri: axum::http::Uri = list.1.parse().unwrap();
    assert_eq!(
        query(&uri)["labelSelector"],
        "app.kubernetes.io/managed-by=oauthrelay,oauthrelay.dev/expires-hour in (500000)"
    );
    assert_eq!(query(&uri)["limit"], "500");
    let delete = requests
        .iter()
        .find(|(method, ..)| method == "DELETE")
        .unwrap();
    assert!(!delete.2["preconditions"]["resourceVersion"].is_null());
}
