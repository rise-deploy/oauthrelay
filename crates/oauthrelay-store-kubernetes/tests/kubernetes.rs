//! Requires an isolated cluster with the generated CRDs and the Dex `authcodes` CRD installed
//! (`tests/kubernetes/run.py`). Run with `--test-threads=1`: the sweeper tests delete every
//! expired record in the namespace, including other tests'.
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
    expiry_hour, expiry_selector, object_name, CreateOutcome, DeleteOutcome, KubeClient,
    KubernetesClient, KubernetesStore, NewRecord, Page, RecordMapping, ReplaceOutcome, Stored,
    SweepReport, TransientRecord, SWEEP_GRACE,
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

/// Where the shipped deployment example's Role lets the `oauthrelay` service account work.
const NAMESPACE: &str = "oauthrelay";
/// Stands in for Dex's namespace.
const DEX_NAMESPACE: &str = "dex";
const TTL: Duration = Duration::from_secs(300);

static SETUP: OnceCell<()> = OnceCell::const_new();
static DEX_SETUP: OnceCell<()> = OnceCell::const_new();
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

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A store over `client` whose clock runs `SWEEP_GRACE` ahead, so that records that expired a
/// moment ago are past the grace the sweeper waits before deleting.
fn store_past_the_grace(
    client: Arc<impl KubernetesClient>,
) -> KubernetesStore<impl KubernetesClient> {
    let grace = u64::try_from(SWEEP_GRACE.as_millis()).unwrap();
    KubernetesStore::with_clock(client, Arc::new(move || now_ms() + grace))
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

async fn apply(admin: &Client, namespace: Option<&str>, value: Value) {
    let kind = value["kind"].as_str().unwrap();
    let group = if kind.starts_with("Role") {
        "rbac.authorization.k8s.io"
    } else {
        ""
    };
    let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, "v1", kind));
    let api: Api<DynamicObject> = match namespace {
        None => Api::all_with(admin.clone(), &resource),
        Some(namespace) => Api::namespaced_with(admin.clone(), namespace, &resource),
    };
    let name = value["metadata"]["name"].as_str().unwrap().to_owned();
    api.patch(
        &name,
        &PatchParams::apply("oauthrelay-tests"),
        &Patch::Apply(value),
    )
    .await
    .unwrap();
}

/// Applies the namespace, service account, role and binding of the shipped deployment example.
async fn apply_deployment_rbac(admin: &Client) {
    for document in
        serde_yaml::Deserializer::from_str(include_str!("../../../deploy/kubernetes.yaml"))
    {
        let value = Value::deserialize(document).unwrap();
        match value["kind"].as_str().unwrap() {
            "Deployment" | "Service" => {}
            "Namespace" => apply(admin, None, value).await,
            _ => apply(admin, Some(NAMESPACE), value).await,
        }
    }
}

/// Gives the `oauthrelay` service account the rule that `deploy/kubernetes.yaml` documents for
/// the Dex mapping, in the namespace that stands in for Dex's.
async fn apply_dex_rbac(admin: &Client) {
    apply(
        admin,
        None,
        json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":DEX_NAMESPACE}}),
    )
    .await;
    apply(
        admin,
        Some(DEX_NAMESPACE),
        json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role",
            "metadata":{"name":"oauthrelay-store","namespace":DEX_NAMESPACE},
            "rules":[{"apiGroups":["dex.coreos.com"],"resources":["authcodes"],
                "verbs":["get","list","create","update","delete"]}]}),
    )
    .await;
    apply(
        admin,
        Some(DEX_NAMESPACE),
        json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
            "metadata":{"name":"oauthrelay-store","namespace":DEX_NAMESPACE},
            "subjects":[{"kind":"ServiceAccount","name":"oauthrelay","namespace":NAMESPACE}],
            "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"oauthrelay-store"}}),
    )
    .await;
}

/// The cluster's administrator, and a client that holds only what the `oauthrelay` service
/// account is granted: the shipped Role, plus the Dex rule in the Dex namespace.
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
    DEX_SETUP
        .get_or_init(|| async { apply_dex_rbac(&admin).await })
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

/// Where the records of one mapping live, and a store over the service account's credentials.
struct Env {
    mapping: RecordMapping,
    namespace: &'static str,
    admin: Client,
    client: Arc<KubeClient>,
    store: KubernetesStore<KubeClient>,
}

impl Env {
    async fn new(mapping: RecordMapping) -> Self {
        let namespace = match mapping {
            RecordMapping::TransientRecord => NAMESPACE,
            RecordMapping::DexAuthCode => DEX_NAMESPACE,
        };
        let clients = clients().await;
        let client = Arc::new(KubeClient::new(clients.service_account, namespace, mapping));
        let store = KubernetesStore::new(client.clone());
        // Role bindings take a moment to reach the authorizer.
        let mut attempts = 0;
        while let Err(error) = store.probe().await {
            attempts += 1;
            assert!(attempts < 20, "probe keeps failing: {error:#}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Self {
            mapping,
            namespace,
            admin: clients.admin,
            client,
            store,
        }
    }

    /// Direct, administrator access to the stored objects.
    fn raw(&self) -> Api<DynamicObject> {
        Api::namespaced_with(
            self.admin.clone(),
            self.namespace,
            &self.mapping.api_resource(),
        )
    }

    async fn stored(&self, key: &str) -> Option<DynamicObject> {
        self.raw()
            .get_opt(&self.mapping.object_name(key))
            .await
            .unwrap()
    }
}

/// The scenarios that hold for every mapping.
mod scenarios {
    use super::*;

    pub async fn basic_operations(env: &Env) {
        let store = &env.store;
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
        assert!(env.stored(&key).await.is_none());
    }

    pub async fn one_winner_among_twenty_creators(
        env: &Env,
        store: Arc<KubernetesStore<KubeClient>>,
    ) {
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
        let value = store.get(&key).await.unwrap().unwrap().value;
        assert!(value.starts_with(b"writer-"));
        assert!(env.stored(&key).await.is_some());
    }

    pub async fn one_winner_per_swap_round(store: Arc<KubernetesStore<KubeClient>>) {
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

    pub async fn expiry_takeover_and_sweep(env: &Env) {
        let store = &env.store;
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
        assert!(env.stored(&key).await.is_some());

        let swept = unique_key("replay");
        assert!(store
            .put_if_absent(&swept, b"x", Duration::from_millis(100))
            .await
            .unwrap());
        let live = unique_key("replay");
        assert!(store.put_if_absent(&live, b"x", TTL).await.unwrap());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let report = store_past_the_grace(env.client.clone())
            .sweep()
            .await
            .unwrap();
        assert!(report.deleted >= 2, "{report:?}");
        assert!(env.stored(&key).await.is_none());
        assert!(env.stored(&swept).await.is_none());
        assert!(env.stored(&live).await.is_some());

        // A record that expired but was not swept is taken over by the next writer.
        let stale = unique_key("replay");
        assert!(store
            .put_if_absent(&stale, b"old", Duration::from_millis(100))
            .await
            .unwrap());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(store.put_if_absent(&stale, b"new", TTL).await.unwrap());
        assert_eq!(store.get(&stale).await.unwrap().unwrap().value, b"new");
    }

    pub async fn renewed_record_survives_a_sweep(env: &Env) {
        let key = unique_key("refresh");
        assert!(env
            .store
            .put_if_absent(&key, b"renew-me", Duration::from_millis(100))
            .await
            .unwrap());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let racing = store_past_the_grace(Arc::new(RenewAfterList {
            inner: env.client.clone(),
        }));
        let SweepReport { skipped, .. } = racing.sweep().await.unwrap();
        assert!(skipped >= 1);
        // Renewed with a far-future expiry and a new value: the delete's precondition failed.
        assert_eq!(
            env.store.get(&key).await.unwrap().unwrap().value,
            b"renewed"
        );
    }
}

/// Renews every `renew-me` record right after the sweeper listed it, as a concurrent replica
/// would.
struct RenewAfterList {
    inner: Arc<KubeClient>,
}

#[async_trait::async_trait]
impl KubernetesClient for RenewAfterList {
    fn target(&self) -> String {
        self.inner.target()
    }
    fn install_hint(&self) -> String {
        self.inner.install_hint()
    }
    fn object_name(&self, key: &str) -> String {
        self.inner.object_name(key)
    }
    async fn permits(&self, verb: &str) -> anyhow::Result<bool> {
        self.inner.permits(verb).await
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
        for object in page
            .items
            .iter()
            .filter(|object| object.value == b"renew-me")
        {
            let renewed = NewRecord {
                name: &object.name,
                key: "refresh:renewed",
                value: b"renewed",
                // 2100-01-01T00:00:00Z.
                expires_at_ms: 4_102_444_800_000,
            };
            let outcome = self
                .inner
                .replace(renewed, &object.resource_version)
                .await?;
            assert_eq!(outcome, ReplaceOutcome::Replaced);
        }
        Ok(page)
    }
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn the_shipped_role_is_enough_and_confined_to_its_namespace() {
    let env = Env::new(RecordMapping::TransientRecord).await;
    scenarios::basic_operations(&env).await;

    // The record is a labelled TransientRecord that `kubectl` users can inspect.
    let key = unique_key("refresh");
    assert!(env
        .store
        .put_if_absent(&key, b"\x00\xff", TTL)
        .await
        .unwrap());
    let object = env.stored(&key).await.unwrap();
    let labels = object.metadata.labels.clone().unwrap();
    assert_eq!(labels["oauthrelay.dev/purpose"], "refresh");
    assert_eq!(object.data["spec"]["key"], key);
    assert_eq!(object.data["spec"]["value"], "AP8=");
    // The hour label is within an hour of "now plus TTL" (the two clocks differ by moments).
    let hour: u64 = labels["oauthrelay.dev/expires-hour"].parse().unwrap();
    assert!(hour.abs_diff(expiry_hour(now_ms() + TTL.as_millis() as u64)) <= 1);

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
    assert!(
        format!("{error:#}").to_lowercase().contains("forbidden"),
        "{error:#}"
    );
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn twenty_concurrent_put_if_absent_calls_have_exactly_one_winner() {
    let env = Env::new(RecordMapping::TransientRecord).await;
    let store = Arc::new(KubernetesStore::new(env.client.clone()));
    scenarios::one_winner_among_twenty_creators(&env, store).await;
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn compare_and_swap_under_contention_has_one_winner_per_round() {
    let env = Env::new(RecordMapping::TransientRecord).await;
    scenarios::one_winner_per_swap_round(Arc::new(KubernetesStore::new(env.client.clone()))).await;
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn expired_records_are_absent_replaceable_and_swept() {
    scenarios::expiry_takeover_and_sweep(&Env::new(RecordMapping::TransientRecord).await).await;
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn a_record_renewed_after_the_sweeper_listed_it_survives() {
    scenarios::renewed_record_survives_a_sweep(&Env::new(RecordMapping::TransientRecord).await)
        .await;
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn the_crd_schema_validates_records() {
    let env = Env::new(RecordMapping::TransientRecord).await;
    let api = Api::<DynamicObject>::namespaced_with(
        env.admin.clone(),
        NAMESPACE,
        &TransientRecord::api_resource(),
    );
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

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn dex_auth_codes_work_through_a_role_scoped_to_authcodes() {
    let env = Env::new(RecordMapping::DexAuthCode).await;
    scenarios::basic_operations(&env).await;

    // The record is an AuthCode with the Dex-safety fields, and the API server (whose schema
    // accepts any object, like Dex's own) stored it as written.
    let key = unique_key("replay");
    assert!(env
        .store
        .put_if_absent(&key, b"\x00\xff", TTL)
        .await
        .unwrap());
    let object = env.stored(&key).await.unwrap();
    assert_eq!(
        object.types.as_ref().unwrap().api_version,
        "dex.coreos.com/v1"
    );
    assert_eq!(object.types.as_ref().unwrap().kind, "AuthCode");
    // Named to sort after every code Dex wrote, so Dex's garbage collector, which reads the
    // first 500 names, is never starved of its own.
    let name = object.metadata.name.clone().unwrap();
    assert_eq!(name, env.mapping.object_name(&key));
    assert!(
        name.starts_with("zzzzzzzzzzz") && name.len() == 63,
        "{name}"
    );
    assert_eq!(
        object.metadata.labels.unwrap()["app.kubernetes.io/managed-by"],
        "oauthrelay"
    );
    assert_eq!(object.data["connectorData"], "AP8=");
    assert_eq!(object.data["clientID"], "oauthrelay:transient-record");
    assert_eq!(
        object.data["redirectURI"],
        "urn:oauthrelay:transient-record"
    );
    assert_eq!(object.data["code_challenge"].as_str().unwrap().len(), 43);
    assert!(object.data.get("claims").is_none() && object.data.get("scopes").is_none());
    let expiry = object.data["expiry"].as_str().unwrap();
    assert!(expiry.ends_with('Z') && expiry.contains('.'), "{expiry}");

    // The Dex rule is scoped to Dex's namespace: the oauthrelay namespace's Role has none.
    let elsewhere = KubeClient::new(
        clients().await.service_account,
        NAMESPACE,
        RecordMapping::DexAuthCode,
    );
    let error = KubernetesStore::new(Arc::new(elsewhere))
        .probe()
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").to_lowercase().contains("forbidden"),
        "{error:#}"
    );
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn dex_auth_codes_have_exactly_one_winner_among_concurrent_writers() {
    let env = Env::new(RecordMapping::DexAuthCode).await;
    let store = Arc::new(KubernetesStore::new(env.client.clone()));
    scenarios::one_winner_among_twenty_creators(&env, store.clone()).await;
    scenarios::one_winner_per_swap_round(store).await;
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn dex_auth_codes_expire_get_swept_and_survive_renewal() {
    let env = Env::new(RecordMapping::DexAuthCode).await;
    scenarios::expiry_takeover_and_sweep(&env).await;
    scenarios::renewed_record_survives_a_sweep(&env).await;
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn the_sweeper_never_touches_auth_codes_that_dex_wrote() {
    let env = Env::new(RecordMapping::DexAuthCode).await;
    // What Dex itself writes: no managed-by label, a real client, long expired.
    let dex_code: DynamicObject = serde_json::from_value(json!({
        "apiVersion": "dex.coreos.com/v1",
        "kind": "AuthCode",
        "metadata": {"name": "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dpo5zq", "namespace": DEX_NAMESPACE},
        "clientID": "example-app",
        "redirectURI": "https://app.example/callback",
        "connectorID": "mock",
        "connectorData": "c2VjcmV0",
        "claims": {"userID": "u1", "username": "kilgore", "email": "kilgore@kilgore.trout"},
        "scopes": ["openid"],
        "expiry": "2001-01-01T00:00:00Z",
    }))
    .unwrap();
    env.raw()
        .create(&PostParams::default(), &dex_code)
        .await
        .unwrap();
    let expired = unique_key("replay");
    assert!(env
        .store
        .put_if_absent(&expired, b"x", Duration::from_millis(100))
        .await
        .unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let report = store_past_the_grace(env.client.clone())
        .sweep()
        .await
        .unwrap();
    assert!(report.deleted >= 1);
    assert!(env.stored(&expired).await.is_none());
    assert!(env
        .raw()
        .get_opt("mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dpo5zq")
        .await
        .unwrap()
        .is_some());
    env.raw()
        .delete(
            "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dpo5zq",
            &DeleteParams::default(),
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn the_expiry_hour_selector_and_the_bucketed_sweeper_work_against_the_api_server() {
    let env = Env::new(RecordMapping::TransientRecord).await;
    let key = unique_key("replay");
    assert!(env
        .store
        .put_if_absent(&key, b"x", Duration::from_millis(100))
        .await
        .unwrap());
    let object = env.stored(&key).await.unwrap();
    let hour: u64 = object.metadata.labels.unwrap()["oauthrelay.dev/expires-hour"]
        .parse()
        .unwrap();
    let name = object_name(&key);
    // The `in (...)` selector, with other hours alongside, selects the record's bucket only.
    let selected = env
        .client
        .list(&expiry_selector([hour - 1, hour, hour + 1]), 500, None)
        .await
        .unwrap();
    assert!(selected.items.iter().any(|object| object.name == name));
    let elsewhere = env
        .client
        .list(&expiry_selector([hour + 1000, hour + 1001]), 500, None)
        .await
        .unwrap();
    assert!(elsewhere.items.iter().all(|object| object.name != name));

    // The sweeper task: its first pass is full, later ones are bucketed. The clock runs exactly
    // the grace ahead, so a record is deletable as soon as it expired.
    let grace = u64::try_from(SWEEP_GRACE.as_millis()).unwrap();
    let sweeping =
        KubernetesStore::with_clock(env.client.clone(), Arc::new(move || now_ms() + grace))
            .with_sweeper(Duration::from_millis(200));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(env.stored(&key).await.is_none(), "the full pass deletes it");
    let later = unique_key("replay");
    assert!(env
        .store
        .put_if_absent(&later, b"x", Duration::from_millis(100))
        .await
        .unwrap());
    let mut attempts = 0;
    while env.stored(&later).await.is_some() {
        attempts += 1;
        assert!(attempts < 50, "a bucketed sweep never deleted the record");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(sweeping);
}
