//! Helpers shared by the Kind test targets: the administrator's and the `oauthrelay` service
//! account's clients, and the RBAC the shipped deployment example and the Dex mapping document.
#![allow(dead_code)]
use k8s_openapi::api::{
    authentication::v1::{TokenRequest, TokenRequestSpec},
    core::v1::ServiceAccount,
};
use kube::{
    api::{DynamicObject, Patch, PatchParams, PostParams},
    core::{ApiResource, GroupVersionKind},
    Api, Client, Config,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::OnceCell;

/// Where the shipped deployment example's Role lets the `oauthrelay` service account work.
pub const NAMESPACE: &str = "oauthrelay";
/// Dex's namespace, or the one that stands in for it.
pub const DEX_NAMESPACE: &str = "dex";

static SETUP: OnceCell<()> = OnceCell::const_new();
static DEX_SETUP: OnceCell<()> = OnceCell::const_new();
static COUNTER: AtomicU32 = AtomicU32::new(0);

pub async fn admin_config() -> Config {
    let path = std::env::var("OAUTHRELAY_KUBERNETES_TEST_KUBECONFIG")
        .expect("explicit disposable test kubeconfig required");
    Config::from_custom_kubeconfig(
        kube::config::Kubeconfig::read_from(path).unwrap(),
        &Default::default(),
    )
    .await
    .unwrap()
}

pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A key no other test, and no earlier run, has used.
pub fn unique_key(purpose: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{purpose}:test-{nanos}-{}",
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

pub async fn apply(admin: &Client, namespace: Option<&str>, value: Value) {
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
pub async fn apply_deployment_rbac(admin: &Client) {
    for document in
        serde_yaml::Deserializer::from_str(include_str!("../../../../deploy/kubernetes.yaml"))
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
pub async fn apply_dex_rbac(admin: &Client) {
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
pub struct Clients {
    pub admin: Client,
    pub service_account: Client,
}

pub async fn clients() -> Clients {
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
