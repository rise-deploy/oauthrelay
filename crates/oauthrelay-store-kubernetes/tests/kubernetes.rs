//! Requires an isolated cluster with the generated CRDs installed.
use k8s_openapi::api::{
    authentication::v1::{TokenRequest, TokenRequestSpec},
    core::v1::ServiceAccount,
};
use kube::{
    api::{DeleteParams, DynamicObject, Patch, PatchParams, PostParams},
    core::{ApiResource, GroupVersionKind},
    Api, Client, Config, CustomResourceExt,
};
use oauthrelay_core::TransientStore;
use oauthrelay_store_kubernetes::{
    object_name, CreateOutcome, DeleteOutcome, KubeClient, KubernetesClient, KubernetesStore,
    NewRecord, Page, RecordMapping, ReplaceOutcome, Stored, SweepReport, TransientRecord,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::OnceCell;

const NAMESPACE: &str = "oauthrelay";
const TTL: Duration = Duration::from_secs(300);

static SETUP: OnceCell<()> = OnceCell::const_new();
static COUNTER: AtomicU32 = AtomicU32::new(0);

async fn admin_config() -> Config {
    let path = std::env::var("OAUTHRELAY_KUBERNETES_TEST_KUBECONFIG")
        .expect("explicit disposable test kubeconfig required");
    Config::from_custom_kubeconfig(
        kube::config::Kubeconfig::read_from(path).unwrap(),
        &Default::default(),
    )
    .await
    .unwrap()
}

/// A key no other test, and no earlier run, has used.
fn unique_key(purpose: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{purpose}:test-{nanos}-{}",
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

/// Applies the namespace, service account, role and binding of the shipped deployment example.
async fn apply_deployment_rbac(admin: &Client) {
    for document in
        serde_yaml::Deserializer::from_str(include_str!("../../../deploy/kubernetes.yaml"))
    {
        let value = Value::deserialize(document).unwrap();
        let kind = value["kind"].as_str().unwrap();
        if matches!(kind, "Deployment" | "Service") {
            continue;
        }
        let group = if kind.starts_with("Role") {
            "rbac.authorization.k8s.io"
        } else {
            ""
        };
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, "v1", kind));
        let api: Api<DynamicObject> = if kind == "Namespace" {
            Api::all_with(admin.clone(), &resource)
        } else {
            Api::namespaced_with(admin.clone(), NAMESPACE, &resource)
        };
        api.patch(
            "oauthrelay",
            &PatchParams::apply("oauthrelay-tests"),
            &Patch::Apply(value),
        )
        .await
        .unwrap();
    }
}

/// The cluster's administrator, and a client that holds only what the shipped Role grants the
/// `oauthrelay` service account.
struct Clients {
    admin: Client,
    service_account: Client,
}

async fn clients() -> Clients {
    let config = admin_config().await;
    let admin = Client::try_from(config.clone()).unwrap();
    SETUP
        .get_or_init(|| async { apply_deployment_rbac(&admin).await })
        .await;
    let token = Api::<ServiceAccount>::namespaced(admin.clone(), NAMESPACE)
        .create_token_request(
            "oauthrelay",
            &PostParams::default(),
            &TokenRequest {
                spec: TokenRequestSpec {
                    audiences: vec![],
                    expiration_seconds: Some(600),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .status
        .unwrap()
        .token;
    let mut restricted = config;
    restricted.auth_info = kube::config::AuthInfo {
        token: Some(token.into()),
        ..Default::default()
    };
    Clients {
        admin,
        service_account: Client::try_from(restricted).unwrap(),
    }
}

/// A store over the service account's credentials.
async fn store_as_service_account() -> (Client, Arc<KubeClient>, KubernetesStore<KubeClient>) {
    let clients = clients().await;
    let client = Arc::new(KubeClient::new(
        clients.service_account,
        NAMESPACE,
        RecordMapping::TransientRecord,
    ));
    (clients.admin, client.clone(), KubernetesStore::new(client))
}

fn raw_api(admin: &Client) -> Api<DynamicObject> {
    Api::namespaced_with(admin.clone(), NAMESPACE, &TransientRecord::api_resource())
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn the_shipped_role_is_enough_and_confined_to_its_namespace() {
    let (admin, _, store) = store_as_service_account().await;
    store.probe().await.unwrap();
    let key = unique_key("replay");
    assert!(store.put_if_absent(&key, b"1", TTL).await.unwrap());
    assert!(!store.put_if_absent(&key, b"2", TTL).await.unwrap());
    let entry = store.get(&key).await.unwrap().unwrap();
    assert_eq!(entry.value, b"1");
    assert!(entry.expires_in <= TTL && entry.expires_in > TTL - Duration::from_secs(30));
    assert!(store.compare_and_swap(&key, b"1", b"2", TTL).await.unwrap());
    assert!(!store.compare_and_swap(&key, b"1", b"3", TTL).await.unwrap());
    assert_eq!(store.get(&key).await.unwrap().unwrap().value, b"2");
    store.delete(&key).await.unwrap();
    store.delete(&key).await.unwrap();
    assert_eq!(store.get(&key).await.unwrap(), None);

    // The record is a labelled TransientRecord that `kubectl` users can inspect.
    let key = unique_key("refresh");
    assert!(store.put_if_absent(&key, b"\x00\xff", TTL).await.unwrap());
    let object = raw_api(&admin).get(&object_name(&key)).await.unwrap();
    assert_eq!(
        object.metadata.labels.unwrap()["oauthrelay.dev/purpose"],
        "refresh"
    );
    assert_eq!(object.data["spec"]["key"], key);
    assert_eq!(object.data["spec"]["value"], "AP8=");

    // The role is a Role, not a ClusterRole: another namespace is off limits.
    let elsewhere = KubeClient::new(
        clients().await.service_account,
        "default",
        RecordMapping::TransientRecord,
    );
    let error = KubernetesStore::new(Arc::new(elsewhere))
        .probe()
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("Forbidden"), "{error:#}");
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn twenty_concurrent_put_if_absent_calls_have_exactly_one_winner() {
    let (_, _, store) = store_as_service_account().await;
    let store = Arc::new(store);
    let key = unique_key("replay");
    let mut tasks = Vec::new();
    for index in 0..20 {
        let (store, key) = (store.clone(), key.clone());
        tasks.push(tokio::spawn(async move {
            store
                .put_if_absent(&key, format!("writer-{index}").as_bytes(), TTL)
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
        .get(&key)
        .await
        .unwrap()
        .unwrap()
        .value
        .starts_with(b"writer-"));
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn compare_and_swap_under_contention_has_one_winner_per_round() {
    let (_, _, store) = store_as_service_account().await;
    let store = Arc::new(store);
    let key = unique_key("refresh");
    assert!(store.put_if_absent(&key, b"round-0", TTL).await.unwrap());
    let mut current = b"round-0".to_vec();
    for round in 1..=3 {
        let mut tasks = Vec::new();
        for index in 0..20 {
            let (store, key, expected) = (store.clone(), key.clone(), current.clone());
            tasks.push(tokio::spawn(async move {
                let new = format!("round-{round}-writer-{index}").into_bytes();
                let won = store
                    .compare_and_swap(&key, &expected, &new, TTL)
                    .await
                    .unwrap();
                (won, new)
            }));
        }
        let mut winners = Vec::new();
        for task in tasks {
            let (won, new) = task.await.unwrap();
            if won {
                winners.push(new);
            }
        }
        assert_eq!(winners.len(), 1, "round {round}");
        assert_eq!(store.get(&key).await.unwrap().unwrap().value, winners[0]);
        current = winners.pop().unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn expired_records_are_absent_replaceable_and_swept() {
    let (admin, _, store) = store_as_service_account().await;
    let key = unique_key("replay");
    assert!(store
        .put_if_absent(&key, b"old", Duration::from_millis(1500))
        .await
        .unwrap());
    assert!(store.get(&key).await.unwrap().is_some());
    assert!(!store.put_if_absent(&key, b"other", TTL).await.unwrap());
    tokio::time::sleep(Duration::from_millis(1700)).await;
    assert_eq!(store.get(&key).await.unwrap(), None);
    assert!(!store
        .compare_and_swap(&key, b"old", b"new", TTL)
        .await
        .unwrap());
    // The object is still there; it only reads as absent.
    assert!(raw_api(&admin)
        .get_opt(&object_name(&key))
        .await
        .unwrap()
        .is_some());

    let expired_key = unique_key("replay");
    assert!(store
        .put_if_absent(&expired_key, b"x", Duration::from_millis(100))
        .await
        .unwrap());
    let live_key = unique_key("replay");
    assert!(store.put_if_absent(&live_key, b"x", TTL).await.unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let report = store.sweep().await.unwrap();
    assert!(report.deleted >= 2, "{report:?}");
    for gone in [&key, &expired_key] {
        assert!(raw_api(&admin)
            .get_opt(&object_name(gone))
            .await
            .unwrap()
            .is_none());
    }
    assert!(raw_api(&admin)
        .get_opt(&object_name(&live_key))
        .await
        .unwrap()
        .is_some());
    // An expired record is replaceable without waiting for the sweeper.
    assert!(store.put_if_absent(&key, b"new", TTL).await.unwrap());
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn put_if_absent_takes_over_an_expired_record_that_is_still_stored() {
    let (admin, _, store) = store_as_service_account().await;
    let key = unique_key("replay");
    assert!(store
        .put_if_absent(&key, b"old", Duration::from_millis(100))
        .await
        .unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(store.put_if_absent(&key, b"new", TTL).await.unwrap());
    assert_eq!(store.get(&key).await.unwrap().unwrap().value, b"new");
    let object = raw_api(&admin).get(&object_name(&key)).await.unwrap();
    assert_eq!(object.data["spec"]["key"], key);
}

/// Renews every listed record right after the sweeper listed it, as a concurrent replica would.
struct RenewAfterList {
    inner: Arc<KubeClient>,
}

#[async_trait::async_trait]
impl KubernetesClient for RenewAfterList {
    fn target(&self) -> String {
        self.inner.target()
    }
    async fn get(&self, name: &str) -> anyhow::Result<Option<Stored>> {
        self.inner.get(name).await
    }
    async fn create(&self, record: NewRecord<'_>) -> anyhow::Result<CreateOutcome> {
        self.inner.create(record).await
    }
    async fn replace(
        &self,
        record: NewRecord<'_>,
        resource_version: &str,
    ) -> anyhow::Result<ReplaceOutcome> {
        self.inner.replace(record, resource_version).await
    }
    async fn delete(
        &self,
        name: &str,
        resource_version: Option<&str>,
    ) -> anyhow::Result<DeleteOutcome> {
        self.inner.delete(name, resource_version).await
    }
    async fn list(
        &self,
        label_selector: &str,
        limit: u32,
        continue_token: Option<&str>,
    ) -> anyhow::Result<Page> {
        let page = self
            .inner
            .list(label_selector, limit, continue_token)
            .await?;
        for object in &page.items {
            let renewed = NewRecord {
                name: &object.name,
                key: "replay:renewed",
                value: b"renewed",
                // 2100-01-01T00:00:00Z.
                expires_at_ms: 4_102_444_800_000,
            };
            if object.value == b"renew-me" {
                let outcome = self
                    .inner
                    .replace(renewed, &object.resource_version)
                    .await?;
                assert_eq!(outcome, ReplaceOutcome::Replaced);
            }
        }
        Ok(page)
    }
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn a_record_renewed_after_the_sweeper_listed_it_survives() {
    let (_, client, store) = store_as_service_account().await;
    let key = unique_key("refresh");
    assert!(store
        .put_if_absent(&key, b"renew-me", Duration::from_millis(100))
        .await
        .unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let racing = KubernetesStore::new(Arc::new(RenewAfterList { inner: client }));
    let SweepReport { skipped, .. } = racing.sweep().await.unwrap();
    assert!(skipped >= 1);
    // Renewed with a far-future expiry and a new value: the delete's precondition failed.
    assert_eq!(store.get(&key).await.unwrap().unwrap().value, b"renewed");
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn the_crd_schema_validates_records() {
    let (admin, _, _) = store_as_service_account().await;
    let api = raw_api(&admin);
    let dry_run = PostParams {
        dry_run: true,
        ..Default::default()
    };
    let record = |name: &str, spec: Value| -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "oauthrelay.dev/v1alpha1",
            "kind": "TransientRecord",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "spec": spec,
        }))
        .unwrap()
    };
    let valid = json!({"key":"replay:a","value":"AA==","expiresAt":"2030-01-01T00:00:00.000Z"});
    api.create(&dry_run, &record("schema-valid", valid.clone()))
        .await
        .unwrap();
    for (what, spec) in [
        (
            "no key",
            json!({"value":"AA==","expiresAt":"2030-01-01T00:00:00Z"}),
        ),
        (
            "no value",
            json!({"key":"k","expiresAt":"2030-01-01T00:00:00Z"}),
        ),
        ("no expiry", json!({"key":"k","value":"AA=="})),
        (
            "empty key",
            json!({"key":"","value":"AA==","expiresAt":"2030-01-01T00:00:00Z"}),
        ),
        (
            "long key",
            json!({"key":"k".repeat(1025),"value":"AA==","expiresAt":"2030-01-01T00:00:00Z"}),
        ),
        (
            "bad expiry",
            json!({"key":"k","value":"AA==","expiresAt":"tomorrow"}),
        ),
        (
            "numeric expiry",
            json!({"key":"k","value":"AA==","expiresAt":1893456000}),
        ),
    ] {
        let result = api.create(&dry_run, &record("schema-invalid", spec)).await;
        assert!(
            matches!(&result, Err(kube::Error::Api(status)) if status.code == 422),
            "{what}: {result:?}"
        );
    }
    // The typed resource round-trips through the API server.
    let created = api
        .create(&PostParams::default(), &record("schema-typed", valid))
        .await
        .unwrap();
    let typed: TransientRecord =
        serde_json::from_value(serde_json::to_value(created).unwrap()).unwrap();
    assert_eq!(typed.spec.key, "replay:a");
    api.delete("schema-typed", &DeleteParams::default())
        .await
        .unwrap();
}
