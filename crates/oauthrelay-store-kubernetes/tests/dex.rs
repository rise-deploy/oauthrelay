//! Runs the Dex `AuthCode` mapping against a real Dex with Kubernetes storage, in the disposable
//! Kind cluster (`tests/kubernetes/run.py` deploys Dex and port-forwards it, then sets
//! `OAUTHRELAY_DEX_TEST_ISSUER` to its issuer URL). Run with `--test-threads=1`.
//!
//! oauthrelay's own sweeper is never started here, so every deletion is Dex's.
mod common;

use common::{clients, unique_key, DEX_NAMESPACE};
use kube::{
    api::{DeleteParams, DynamicObject, ListParams, PostParams},
    Api, Client,
};
use oauthrelay_core::TransientStore;
use oauthrelay_store_kubernetes::{KubeClient, KubernetesStore, RecordMapping, MANAGED_SELECTOR};
use reqwest::{redirect::Policy, StatusCode, Url};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

/// The static clients of `tests/kubernetes/dex.yaml`.
const CONFIDENTIAL_CLIENT: &str = "oauthrelay-test";
const CONFIDENTIAL_SECRET: &str = "oauthrelay-test-secret";
const CONFIDENTIAL_REDIRECT: &str = "http://127.0.0.1:18080/callback";
const DEVICE_CLIENT: &str = "oauthrelay-device";
/// What the store writes into every `AuthCode` it owns.
const RECORD_REDIRECT: &str = "urn:oauthrelay:transient-record";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

const TTL: Duration = Duration::from_secs(300);
/// Dex's garbage collector runs every five minutes and the interval is not configurable, so
/// the wait for a run is bounded by that plus a margin.
const GC_DEADLINE: Duration = Duration::from_secs(6 * 60);

struct DexEnv {
    issuer: String,
    http: reqwest::Client,
    admin: Client,
    store: Arc<KubernetesStore<KubeClient>>,
}

impl DexEnv {
    async fn new() -> Self {
        let issuer = std::env::var("OAUTHRELAY_DEX_TEST_ISSUER")
            .expect("OAUTHRELAY_DEX_TEST_ISSUER must name the port-forwarded Dex issuer");
        let clients = clients().await;
        let client = Arc::new(KubeClient::new(
            clients.service_account,
            DEX_NAMESPACE,
            RecordMapping::DexAuthCode,
        ));
        let store = Arc::new(KubernetesStore::new(client.clone()));
        // Role bindings take a moment to reach the authorizer.
        let mut attempts = 0;
        while let Err(error) = store.probe().await {
            attempts += 1;
            assert!(attempts < 20, "probe keeps failing: {error:#}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Self {
            issuer,
            http: reqwest::Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            admin: clients.admin,
            store,
        }
    }

    /// Direct, administrator access to the stored `AuthCode` objects.
    fn raw(&self) -> Api<DynamicObject> {
        Api::namespaced_with(
            self.admin.clone(),
            DEX_NAMESPACE,
            &RecordMapping::DexAuthCode.api_resource(),
        )
    }

    async fn stored(&self, key: &str) -> Option<DynamicObject> {
        self.raw()
            .get_opt(&RecordMapping::DexAuthCode.object_name(key))
            .await
            .unwrap()
    }

    async fn put(&self, key: &str, value: &[u8], ttl: Duration) {
        assert!(self.store.put_if_absent(key, value, ttl).await.unwrap());
    }

    /// Asserts that the record is still stored, through the store and as an object, with `value`.
    async fn assert_intact(&self, key: &str, value: &[u8]) {
        let entry = self.store.get(key).await.unwrap();
        assert_eq!(
            entry.map(|entry| entry.value),
            Some(value.to_vec()),
            "{key}"
        );
        assert!(self.stored(key).await.is_some(), "{key}");
    }

    async fn discovery_status(&self) -> StatusCode {
        self.http
            .get(format!("{}/.well-known/openid-configuration", self.issuer))
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Logs in through the mock connector as the confidential client, without following the
    /// last redirect (to a URL nothing listens on), and returns that redirect.
    async fn authorization_code_login(&self) -> Url {
        let mut authorize = Url::parse(&format!("{}/auth", self.issuer)).unwrap();
        authorize
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", CONFIDENTIAL_CLIENT)
            .append_pair("redirect_uri", CONFIDENTIAL_REDIRECT)
            .append_pair("state", "dex-test-state")
            .append_pair("scope", "openid email")
            .append_pair("connector_id", "mock");
        let mut current = authorize;
        for _ in 0..12 {
            let response = self.http.get(current.clone()).send().await.unwrap();
            let status = response.status();
            assert!(
                status.is_redirection(),
                "expected a redirect from {current}, got {status}: {}",
                response.text().await.unwrap_or_default()
            );
            let location = response.headers()[reqwest::header::LOCATION]
                .to_str()
                .unwrap()
                .to_owned();
            let next = current.join(&location).unwrap();
            if next.as_str().starts_with(CONFIDENTIAL_REDIRECT) {
                return next;
            }
            current = next;
        }
        panic!("the authorization redirect chain never reached the client");
    }

    /// A request to Dex's token endpoint, authenticated as the confidential client.
    async fn token(&self, form: &[(&str, &str)]) -> (StatusCode, Value) {
        read(
            self.http
                .post(format!("{}/token", self.issuer))
                .basic_auth(CONFIDENTIAL_CLIENT, Some(CONFIDENTIAL_SECRET))
                .form(form)
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    /// Starts a device flow for the public client: `(device_code, user_code)`.
    async fn start_device_flow(&self) -> (String, String) {
        let (status, body) = read(
            self.http
                .post(format!("{}/device/code", self.issuer))
                .form(&[("client_id", DEVICE_CLIENT), ("scope", "openid")])
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["device_code"].as_str().unwrap().to_owned(),
            body["user_code"].as_str().unwrap().to_owned(),
        )
    }

    /// One poll of the token endpoint for a device code.
    async fn poll_device(&self, device_code: &str) -> (StatusCode, Value) {
        read(
            self.http
                .post(format!("{}/token", self.issuer))
                .form(&[
                    ("grant_type", DEVICE_GRANT),
                    ("device_code", device_code),
                    ("client_id", DEVICE_CLIENT),
                ])
                .send()
                .await
                .unwrap(),
        )
        .await
    }
}

async fn read(response: reqwest::Response) -> (StatusCode, Value) {
    let status = response.status();
    let text = response.text().await.unwrap();
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, body)
}

fn query_parameter(url: &Url, name: &str) -> String {
    url.query_pairs()
        .find(|(candidate, _)| candidate == name)
        .unwrap_or_else(|| panic!("missing {name} in {url}"))
        .1
        .into_owned()
}

#[tokio::test]
#[ignore = "requires the Kind cluster and Dex deployed by mise run kubernetes:test"]
async fn dex_stays_healthy_and_logs_users_in_with_oauthrelay_records_present() {
    let env = DexEnv::new().await;
    assert_eq!(env.discovery_status().await, StatusCode::OK);

    let mut live = Vec::new();
    for index in 0..20 {
        let key = unique_key(if index % 2 == 0 { "replay" } else { "refresh" });
        let value = format!("live-value-{index}");
        env.put(&key, value.as_bytes(), TTL).await;
        live.push((key, value));
    }
    let mut expired = Vec::new();
    for _ in 0..20 {
        let key = unique_key("replay");
        env.put(&key, b"old", Duration::from_millis(100)).await;
        expired.push(key);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Dex's own flow: authorization-code login through the mock connector, then the exchange.
    let redirected = env.authorization_code_login().await;
    assert_eq!(query_parameter(&redirected, "state"), "dex-test-state");
    let code = query_parameter(&redirected, "code");
    let (status, body) = env
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string() && body["id_token"].is_string());

    assert_eq!(env.discovery_status().await, StatusCode::OK);
    for (key, value) in &live {
        env.assert_intact(key, value.as_bytes()).await;
    }
    for key in &expired {
        assert_eq!(env.store.get(key).await.unwrap(), None, "{key}");
    }
}

#[tokio::test]
#[ignore = "requires the Kind cluster and Dex deployed by mise run kubernetes:test"]
async fn dexs_token_endpoint_refuses_oauthrelay_records() {
    let env = DexEnv::new().await;
    let key = unique_key("refresh");
    env.put(&key, b"token-endpoint-value", TTL).await;
    let name = RecordMapping::DexAuthCode.object_name(&key);

    // Once with the redirect URI the record carries, so that the client binding is the only
    // check that can refuse the code, and once with the client's own.
    for redirect_uri in [RECORD_REDIRECT, CONFIDENTIAL_REDIRECT] {
        let (status, body) = env
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", &name),
                ("redirect_uri", redirect_uri),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{redirect_uri}: {body}");
        assert_eq!(body["error"], "invalid_grant", "{redirect_uri}: {body}");
        assert!(body.get("access_token").is_none(), "{body}");
        env.assert_intact(&key, b"token-endpoint-value").await;
    }
}

#[tokio::test]
#[ignore = "requires the Kind cluster and Dex deployed by mise run kubernetes:test"]
async fn dexs_device_callback_refuses_oauthrelay_records() {
    let env = DexEnv::new().await;

    // Control: a genuine device login through the same callback completes, so a refusal below
    // is the record's doing and not a device flow that does not work here.
    let (device_code, user_code) = env.start_device_flow().await;
    let following = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let verified = following
        .post(format!("{}/device/auth/verify_code", env.issuer))
        .form(&[("user_code", user_code.as_str())])
        .send()
        .await
        .unwrap();
    assert!(
        verified.status().is_success(),
        "the control device login failed: {} {}",
        verified.status(),
        verified.text().await.unwrap_or_default()
    );
    let (status, body) = env.poll_device(&device_code).await;
    assert_eq!(status, StatusCode::OK, "control: {body}");
    assert!(body["access_token"].is_string(), "control: {body}");

    // An oauthrelay record presented as the authorization code of a pending device request.
    let key = unique_key("replay");
    env.put(&key, b"device-callback-value", TTL).await;
    let name = RecordMapping::DexAuthCode.object_name(&key);
    let (device_code, user_code) = env.start_device_flow().await;
    let response = env
        .http
        .get(format!("{}/device/callback", env.issuer))
        .query(&[("state", user_code.as_str()), ("code", name.as_str())])
        .send()
        .await
        .unwrap();
    assert!(
        !response.status().is_success() && !response.status().is_redirection(),
        "the device callback accepted an oauthrelay record: {}",
        response.status()
    );
    // No tokens were stored for the device request: it is still pending.
    let (status, body) = env.poll_device(&device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "authorization_pending", "{body}");
    assert!(body.get("access_token").is_none(), "{body}");
    env.assert_intact(&key, b"device-callback-value").await;
}

/// A key and the name of its `AuthCode`.
fn named_key(purpose: &str) -> (String, String) {
    let key = unique_key(purpose);
    let name = RecordMapping::DexAuthCode.object_name(&key);
    (key, name)
}

/// Dex's garbage collector collects expired records, and is not starved of its own expired codes
/// by a namespace holding more than the 500 `AuthCode` objects it lists per run.
///
/// The collector lists the first 500 names in order, so the expired oauthrelay record is chosen
/// to have the lowest name of many candidates, and every live one a higher name: it is in the
/// window, with live records on either side of it, and 500 or more live records follow it.
#[tokio::test]
#[ignore = "requires the Kind cluster and Dex deployed by mise run kubernetes:test"]
async fn dexs_garbage_collector_deletes_expired_records_and_is_not_starved_by_live_ones() {
    const LIVE_TTL: Duration = Duration::from_secs(3600);
    const FILLERS: usize = 520;
    // The Dex-style name that sorts last before oauthrelay's: ten `z`, then `y`.
    const NATIVE_NAME: &str = "zzzzzzzzzzyzzzzzzzzzzzzzz";

    let env = DexEnv::new().await;

    let (expired_key, expired_name) = (0..64)
        .map(|_| named_key("replay"))
        .min_by(|left, right| left.1.cmp(&right.1))
        .unwrap();
    env.put(&expired_key, b"expired", Duration::from_millis(100))
        .await;

    let mut fillers = Vec::new();
    while fillers.len() < FILLERS {
        let (key, name) = named_key("refresh");
        if name > expired_name {
            fillers.push(key);
        }
    }
    for chunk in fillers.chunks(25) {
        let mut tasks = Vec::new();
        for key in chunk {
            let (store, key) = (env.store.clone(), key.clone());
            tasks.push(tokio::spawn(async move {
                store.put_if_absent(&key, b"live", LIVE_TTL).await.unwrap()
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap());
        }
    }

    // What Dex itself would leave behind: an authorization code, long expired, that a name-order
    // window starved by oauthrelay's records would never reach.
    let native: DynamicObject = serde_json::from_value(json!({
        "apiVersion": "dex.coreos.com/v1",
        "kind": "AuthCode",
        "metadata": {"name": NATIVE_NAME, "namespace": DEX_NAMESPACE},
        "clientID": CONFIDENTIAL_CLIENT,
        "redirectURI": CONFIDENTIAL_REDIRECT,
        "connectorID": "mock",
        "connectorData": "c2VjcmV0",
        "claims": {"userID": "u1", "username": "kilgore", "email": "kilgore@kilgore.trout"},
        "scopes": ["openid"],
        "expiry": "2001-01-01T00:00:00Z",
    }))
    .unwrap();
    env.raw()
        .create(&PostParams::default(), &native)
        .await
        .unwrap();
    assert!(NATIVE_NAME < expired_name.as_str());

    let started = Instant::now();
    while env.raw().get_opt(&expired_name).await.unwrap().is_some() {
        if started.elapsed() > GC_DEADLINE {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    // A run deletes in name order within one pass; leave it a moment to finish.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let expired_left = env.raw().get_opt(&expired_name).await.unwrap().is_some();
    let native_left = env.raw().get_opt(NATIVE_NAME).await.unwrap().is_some();
    let filler_names: HashSet<String> = fillers
        .iter()
        .map(|key| RecordMapping::DexAuthCode.object_name(key))
        .collect();
    let live_left = env
        .raw()
        .list(&ListParams::default().labels(MANAGED_SELECTOR))
        .await
        .unwrap()
        .items
        .iter()
        .filter(|object| {
            object
                .metadata
                .name
                .as_ref()
                .is_some_and(|name| filler_names.contains(name))
        })
        .count();
    // Clean up before asserting, so that a failure leaves nothing for the next test to trip on.
    let _ = env
        .raw()
        .delete_collection(
            &DeleteParams::default(),
            &ListParams::default().labels(MANAGED_SELECTOR),
        )
        .await;
    let _ = env
        .raw()
        .delete(NATIVE_NAME, &DeleteParams::default())
        .await;

    assert!(
        !expired_left,
        "Dex's garbage collector did not delete an expired oauthrelay record within {GC_DEADLINE:?}: it either did not run (see the Dex logs) or could not decode the object"
    );
    assert!(
        !native_left,
        "Dex's garbage collector deleted the oauthrelay record but not its own expired code: starved"
    );
    assert_eq!(live_left, FILLERS, "Dex deleted live oauthrelay records");
}
