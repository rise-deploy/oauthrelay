use super::*;
use axum::{
    body::Body,
    http::{Request, Response},
};
use serde_json::{json, Value};
use std::{convert::Infallible, sync::Mutex};
use tokio::sync::mpsc;
use tower::service_fn;

fn upstream(secret: Value) -> Value {
    json!({"apiVersion":"oauthrelay.dev/v1alpha1", "kind":"Upstream",
        "metadata":{"name":"issuer", "namespace":"team", "resourceVersion":"1", "labels":{"app":"oauthrelay"}, "managedFields":[]},
        "spec":{"issuerUrl":"https://issuer.example", "oauthClient":{"clientId":"client", "clientSecret":secret}}})
}
fn relay() -> Value {
    json!({"apiVersion":"oauthrelay.dev/v1alpha1", "kind":"Relay",
        "metadata":{"name":"app", "namespace":"team", "resourceVersion":"1"},
        "spec":{"upstreamRef":{"name":"issuer"}, "clientAuthentication":{"type":"Public"},
        "redirectPolicy":[{"uri":"https://app.example/cb"}]}})
}
fn secret(value: &str) -> Value {
    let mut secret = Secret::default();
    secret.metadata.name = Some("credentials".into());
    secret.metadata.namespace = Some("team".into());
    secret.metadata.resource_version = Some("1".into());
    secret.data = Some(BTreeMap::from([(
        "password".into(),
        k8s_openapi::ByteString(value.as_bytes().to_vec()),
    )]));
    serde_json::to_value(secret).unwrap()
}
fn reference() -> Value {
    json!({"valueFrom":{"secretKeyRef":{"name":"credentials", "key":"password"}}})
}

#[test]
fn namespaces_are_single_labels_and_overrides_take_precedence() {
    assert_eq!(select_namespace(None, "team").unwrap(), "team");
    assert_eq!(select_namespace(Some("other"), "team").unwrap(), "other");
    for bad in ["", "*", "a/b", "A", "a.b", "-a", "a-", &"a".repeat(64)] {
        assert!(select_namespace(Some(bad), "team").is_err(), "{bad}");
    }
}

#[test]
fn kubernetes_metadata_is_accepted_but_namespace_must_match() {
    let resource: Upstream = serde_json::from_value(upstream(json!({"value":"secret"}))).unwrap();
    assert!(documents("other", [resource.clone()], []).is_err());
    assert_eq!(documents("team", [resource], []).unwrap().len(), 1);
}

#[test]
fn relists_are_atomic_and_remove_absent_objects() {
    let mut store = Store::default();
    let resource: Relay = serde_json::from_value(relay()).unwrap();
    assert!(!store.apply(watcher::Event::Init));
    assert!(!store.apply(watcher::Event::InitApply(resource.clone())));
    assert!(!store.ready());
    assert!(store.objects.is_empty());
    assert!(store.apply(watcher::Event::InitDone));
    assert!(store.ready());
    assert_eq!(store.objects.len(), 1);
    store.apply(watcher::Event::Init);
    assert_eq!(store.objects.len(), 1);
    assert!(!store.ready());
    store.apply(watcher::Event::InitDone);
    assert!(store.objects.is_empty());
}

#[test]
fn crds_are_deterministic_namespaced_and_structural() {
    let yaml = crds_yaml().unwrap();
    assert_eq!(yaml, crds_yaml().unwrap());
    let crds: Vec<Value> = serde_yaml::Deserializer::from_str(&yaml)
        .map(|doc| Value::deserialize(doc).unwrap())
        .collect();
    assert_eq!(crds.len(), 2);
    for crd in crds {
        assert_eq!(crd["spec"]["scope"], "Namespaced");
        assert_eq!(crd["spec"]["group"], "oauthrelay.dev");
        assert_eq!(crd["spec"]["versions"][0]["name"], "v1alpha1");
        let schema = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        assert_eq!(schema["properties"]["spec"]["type"], "object");
        assert!(!schema.to_string().contains("$ref"));
        assert!(!schema
            .to_string()
            .contains("x-kubernetes-preserve-unknown-fields"));
    }
}

#[derive(Default)]
struct MockState {
    objects: BTreeMap<String, Vec<Value>>,
    streams: BTreeMap<String, mpsc::UnboundedSender<Result<String, Infallible>>>,
    requests: Vec<String>,
    forbidden: bool,
    paginate: bool,
}
#[derive(Clone, Default)]
struct MockApi(Arc<Mutex<MockState>>);

impl MockApi {
    fn configured() -> Self {
        let api = Self::default();
        api.0.lock().unwrap().objects = BTreeMap::from([
            ("upstreams".into(), vec![upstream(reference())]),
            ("relays".into(), vec![relay()]),
            ("secrets".into(), vec![secret("first\n")]),
        ]);
        api
    }
    fn client(&self) -> Client {
        let state = self.0.clone();
        Client::new(
            service_fn(move |request: Request<kube::client::Body>| {
                let state = state.clone();
                async move {
                    let mut state = state.lock().unwrap();
                    let path = request.uri().path();
                    assert!(
                        path.starts_with("/apis/oauthrelay.dev/v1alpha1/namespaces/team/")
                            || path.starts_with("/api/v1/namespaces/team/"),
                        "{path}"
                    );
                    state.requests.push(request.uri().to_string());
                    if state.forbidden {
                        return Ok::<_, Infallible>(Response::builder().status(403).body(Body::from(json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","message":"forbidden","code":403}).to_string())).unwrap());
                    }
                    let parts: Vec<_> = path.split('/').collect();
                    let ns = parts.iter().position(|p| *p == "team").unwrap();
                    let kind = parts[ns + 1];
                    if request
                        .uri()
                        .query()
                        .unwrap_or_default()
                        .contains("watch=true")
                    {
                        if kind == "secrets" {
                            assert!(request.headers()["accept"]
                                .to_str()
                                .unwrap()
                                .contains("PartialObjectMetadata"));
                        }
                        let (tx, rx) = mpsc::unbounded_channel();
                        state.streams.insert(kind.into(), tx);
                        let stream = futures::stream::unfold(rx, |mut rx| async move {
                            rx.recv().await.map(|event| (event, rx))
                        });
                        return Ok(Response::new(Body::from_stream(stream)));
                    }
                    let items = state.objects.get(kind).cloned().unwrap_or_default();
                    if state.paginate && kind == "upstreams" {
                        let second = request
                            .uri()
                            .query()
                            .unwrap_or_default()
                            .contains("continue=next");
                        let body = json!({"apiVersion":"v1", "kind":"List", "metadata":{"resourceVersion":"1", "continue":if second { "" } else { "next" }}, "items":if second { &items[1..] } else { &items[..1] }});
                        return Ok(Response::new(Body::from(body.to_string())));
                    }
                    let body = if let Some(name) = parts.get(ns + 2) {
                        match items.into_iter().find(|v| v["metadata"]["name"] == *name) {
                        Some(value) => value,
                        None => return Ok(Response::builder().status(404).body(Body::from(json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"missing","code":404}).to_string())).unwrap()),
                    }
                    } else {
                        json!({"apiVersion":"v1", "kind":"List", "metadata":{"resourceVersion":"1"}, "items":items})
                    };
                    Ok(Response::new(Body::from(body.to_string())))
                }
            }),
            "team",
        )
    }
    async fn wait_for_watches(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.0.lock().unwrap().streams.len() == 3 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn event(&self, kind: &str, operation: &str, mut object: Value) {
        object["metadata"]["resourceVersion"] = json!("2");
        let mut state = self.0.lock().unwrap();
        let objects = state.objects.entry(kind.into()).or_default();
        objects.retain(|v| v["metadata"]["name"] != object["metadata"]["name"]);
        if operation != "DELETED" {
            objects.push(object.clone());
        }
        state.streams[kind]
            .send(Ok(format!(
                "{}\n",
                json!({"type":operation,"object":object})
            )))
            .unwrap();
    }
}

async fn next(rx: &mut watch::Receiver<ProviderSnapshot>) -> ProviderSnapshot {
    tokio::time::timeout(Duration::from_secs(5), rx.changed())
        .await
        .unwrap()
        .unwrap();
    rx.borrow_and_update().clone()
}
fn password(snapshot: &ProviderSnapshot) -> &str {
    snapshot
        .upstreams
        .values()
        .next()
        .unwrap()
        .client_secret
        .expose()
}

#[tokio::test]
async fn complete_reads_resolve_secrets_and_enforce_rbac_errors() {
    let api = MockApi::configured();
    let provider = KubernetesProvider::new(api.client(), "team", DEFAULT_REFRESH_INTERVAL).unwrap();
    let snapshot = provider.load().await.unwrap();
    assert_eq!(password(&snapshot), "first\n");
    assert_eq!(snapshot.relays.len(), 1);
    api.0.lock().unwrap().forbidden = true;
    assert!(provider.load().await.is_err());
}

#[tokio::test]
async fn secret_lookup_rejects_missing_keys_invalid_utf8_and_namespace_paths() {
    let api = MockApi::configured();
    let resolver = KubernetesSecrets {
        api: Api::namespaced(api.client(), "team"),
    };
    for source in [
        SecretSource::SecretKeyRef {
            name: "missing".into(),
            key: "password".into(),
        },
        SecretSource::SecretKeyRef {
            name: "credentials".into(),
            key: "missing".into(),
        },
        SecretSource::SecretKeyRef {
            name: "../other/credentials".into(),
            key: "password".into(),
        },
    ] {
        assert!(resolver.resolve_source(&source).await.is_err());
    }
    let mut invalid: Secret = serde_json::from_value(secret("a")).unwrap();
    invalid
        .data
        .as_mut()
        .unwrap()
        .insert("password".into(), k8s_openapi::ByteString(vec![255]));
    api.0.lock().unwrap().objects.insert(
        "secrets".into(),
        vec![serde_json::to_value(invalid).unwrap()],
    );
    assert!(resolver
        .resolve_source(&SecretSource::SecretKeyRef {
            name: "credentials".into(),
            key: "password".into()
        })
        .await
        .is_err());
}

#[tokio::test]
async fn watches_rotate_secrets_retain_invalid_snapshots_and_recover() {
    let api = MockApi::configured();
    let provider =
        Arc::new(KubernetesProvider::new(api.client(), "team", DEFAULT_REFRESH_INTERVAL).unwrap());
    let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
    let task = tokio::spawn(provider.run(tx));
    assert_eq!(password(&next(&mut rx).await), "first\n");
    api.wait_for_watches().await;
    let mut unrelated = secret("unrelated");
    unrelated["metadata"]["name"] = json!("unrelated");
    api.event("secrets", "ADDED", unrelated);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rx.changed())
            .await
            .is_err()
    );
    api.event("secrets", "MODIFIED", secret("rotated"));
    assert_eq!(password(&next(&mut rx).await), "rotated");
    api.event("secrets", "DELETED", secret("rotated"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rx.changed())
            .await
            .is_err()
    );
    assert_eq!(password(&rx.borrow()), "rotated");
    api.event("secrets", "ADDED", secret("restored"));
    assert_eq!(password(&next(&mut rx).await), "restored");
    api.event("upstreams", "DELETED", upstream(reference()));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rx.changed())
            .await
            .is_err()
    );
    api.event("relays", "DELETED", relay());
    assert!(next(&mut rx).await.upstreams.is_empty());
    drop(rx);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn periodic_refresh_retries_without_a_watch_event() {
    let api = MockApi::configured();
    let provider =
        Arc::new(KubernetesProvider::new(api.client(), "team", Duration::from_millis(50)).unwrap());
    let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
    let task = tokio::spawn(provider.run(tx));
    next(&mut rx).await;
    api.0
        .lock()
        .unwrap()
        .objects
        .insert("secrets".into(), vec![secret("periodic")]);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if password(&next(&mut rx).await) == "periodic" {
                break;
            }
        }
    })
    .await
    .unwrap();
    drop(rx);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn paginated_reads_deduplicate_referenced_secrets() {
    let api = MockApi::configured();
    {
        let mut state = api.0.lock().unwrap();
        let mut second = upstream(reference());
        second["metadata"]["name"] = json!("second");
        state.objects.get_mut("upstreams").unwrap().push(second);
        state.paginate = true;
    }
    let provider = KubernetesProvider::new(api.client(), "team", DEFAULT_REFRESH_INTERVAL).unwrap();
    assert_eq!(provider.load().await.unwrap().upstreams.len(), 2);
    let state = api.0.lock().unwrap();
    assert!(state.requests.iter().any(|r| r.contains("continue=next")));
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|r| r.ends_with("/secrets/credentials?") || r.ends_with("/secrets/credentials"))
            .count(),
        1
    );
}

#[tokio::test]
async fn expired_resource_versions_relist_and_remove_absent_resources() {
    let api = MockApi::configured();
    let provider =
        Arc::new(KubernetesProvider::new(api.client(), "team", DEFAULT_REFRESH_INTERVAL).unwrap());
    let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
    let task = tokio::spawn(provider.run(tx));
    next(&mut rx).await;
    api.wait_for_watches().await;
    {
        let mut state = api.0.lock().unwrap();
        state.objects.insert("relays".into(), vec![]);
        state.streams["relays"].send(Ok(format!("{}\n", json!({"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Expired","message":"expired","code":410}})))).unwrap();
    }
    assert!(next(&mut rx).await.relays.is_empty());
    drop(rx);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn invalid_initial_configuration_fails_without_publishing() {
    let api = MockApi::configured();
    api.0
        .lock()
        .unwrap()
        .objects
        .insert("secrets".into(), vec![]);
    let provider =
        Arc::new(KubernetesProvider::new(api.client(), "team", DEFAULT_REFRESH_INTERVAL).unwrap());
    let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
    let result = tokio::time::timeout(Duration::from_secs(5), provider.run(tx))
        .await
        .unwrap();
    assert!(result.is_err());
    assert!(rx.changed().await.is_err());
}

#[tokio::test]
async fn periodic_refresh_observes_absolute_secret_file_changes() {
    let api = MockApi::configured();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret");
    std::fs::write(&path, "file-first").unwrap();
    api.0.lock().unwrap().objects.insert(
        "upstreams".into(),
        vec![upstream(json!({"valueFrom":{"file":{"path":path}}}))],
    );
    let provider =
        Arc::new(KubernetesProvider::new(api.client(), "team", Duration::from_millis(50)).unwrap());
    let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
    let task = tokio::spawn(provider.run(tx));
    assert_eq!(password(&next(&mut rx).await), "file-first");
    std::fs::write(path, "file-second").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if password(&next(&mut rx).await) == "file-second" {
                break;
            }
        }
    })
    .await
    .unwrap();
    drop(rx);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn initial_sync_has_a_deadline_when_rbac_denies_watches() {
    let api = MockApi::configured();
    api.0.lock().unwrap().forbidden = true;
    let provider =
        Arc::new(KubernetesProvider::new(api.client(), "team", DEFAULT_REFRESH_INTERVAL).unwrap());
    let (tx, _rx) = watch::channel(ProviderSnapshot::default());
    let error = provider.run(tx).await.unwrap_err();
    assert!(error.to_string().contains("synchronization timed out"));
}
