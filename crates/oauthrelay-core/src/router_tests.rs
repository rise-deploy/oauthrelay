use super::*;
use crate::{
    ClientAuth, MemoryReplayCache, ProviderSnapshot, RedirectMatcher, SecretString, Upstream,
    XChaChaSealer,
};
use axum::{
    body::Body,
    extract::State,
    http::{Request, Uri},
    routing::{get, post},
};
use http_body_util::BodyExt;
use jsonwebtoken::{
    decode, decode_header, encode, jwk::JwkSet, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use rsa::{
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex as StdMutex,
};
use tower::ServiceExt;

type FormPairs = Vec<(String, String)>;
type RequestCapture = Arc<StdMutex<Vec<FormPairs>>>;

#[derive(Clone)]
struct MockIdpState {
    base: Url,
    capture: MockCapture,
}

#[derive(Clone, Default)]
struct MockCapture {
    authorize: RequestCapture,
    token: RequestCapture,
}

#[derive(Clone, Copy)]
enum EndpointConfiguration {
    Discovered,
    Explicit,
    ExplicitWithoutJwks,
}

async fn mock_discovery(State(state): State<MockIdpState>) -> Json<Value> {
    Json(json!({
        "issuer": state.base,
        "authorization_endpoint": state.base.join("authorize").unwrap(),
        "token_endpoint": state.base.join("token").unwrap(),
        "jwks_uri": state.base.join("jwks").unwrap(),
        "custom_field": "preserved"
    }))
}

async fn mock_authorize(State(state): State<MockIdpState>, uri: Uri) -> Response {
    let query: Vec<(String, String)> =
        url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    state.capture.authorize.lock().unwrap().push(query.clone());
    let value = |name: &str| {
        query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .unwrap()
            .1
            .as_str()
    };
    let mut callback = Url::parse(value("redirect_uri")).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "upstream-code")
        .append_pair("state", value("state"))
        .append_pair("iss", state.base.as_str())
        .append_pair("session_state", "upstream-session");
    found(callback.as_str())
}

async fn mock_token(State(state): State<MockIdpState>, body: String) -> Response {
    state.capture.token.lock().unwrap().push(
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect(),
    );
    if body.contains("grant_type=refresh_token") {
        return Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(header::CONTENT_TYPE, "application/vnd.oauth-refresh+json")
            .body(Body::from(
                r#"{"access_token":"refreshed","token_type":"Bearer"}"#,
            ))
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "application/vnd.oauth-token+json")
        .body(Body::from(
            r#"{"access_token":"access","refresh_token":"refresh","token_type":"Bearer"}"#,
        ))
        .unwrap()
}

async fn mock_jwks() -> Json<Value> {
    Json(json!({ "keys": [] }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayProfile {
    Google,
    Cognito,
}

#[derive(Clone)]
struct SignedFixtureState {
    base: Url,
    issuer: String,
    private_pem: Arc<String>,
    jwks: Value,
    jwks_failures_remaining: Arc<AtomicUsize>,
    nonce: Arc<StdMutex<Option<String>>>,
    authorize: Arc<StdMutex<Vec<(String, String)>>>,
}

async fn signed_discovery(State(state): State<SignedFixtureState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": state.base.join("authorize").unwrap(),
        "token_endpoint": state.base.join("token").unwrap(),
        "jwks_uri": state.base.join("jwks").unwrap(),
        "userinfo_endpoint": state.base.join("userinfo").unwrap(),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

async fn signed_authorize(State(state): State<SignedFixtureState>, uri: Uri) -> Response {
    let query: Vec<(String, String)> =
        url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    *state.authorize.lock().unwrap() = query.clone();
    *state.nonce.lock().unwrap() = query
        .iter()
        .find(|(name, _)| name == "nonce")
        .map(|(_, value)| value.clone());
    let value = |name: &str| {
        query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .unwrap()
            .1
            .as_str()
    };
    let mut callback = Url::parse(value("redirect_uri")).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "signed-fixture-code")
        .append_pair("state", value("state"))
        .append_pair("iss", &state.issuer);
    found(callback.as_str())
}

async fn signed_token(State(state): State<SignedFixtureState>, body: String) -> Response {
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    if form
        .iter()
        .any(|pair| pair == &("grant_type".into(), "refresh_token".into()))
    {
        return Json(json!({
            "access_token": "fixture-refreshed-access-token",
            "expires_in": 3600,
            "scope": "openid email profile",
            "token_type": "Bearer"
        }))
        .into_response();
    }

    let access_token = "fixture-access-token";
    let at_hash = URL_SAFE_NO_PAD.encode(&Sha256::digest(access_token.as_bytes())[..16]);
    let mut claims = json!({
        "iss": state.issuer,
        "sub": "fixture-subject",
        "aud": "upstream-client",
        "azp": "upstream-client",
        "iat": unix_now(),
        "exp": unix_now() + 3600,
        "nonce": state.nonce.lock().unwrap().clone().unwrap(),
        "at_hash": at_hash,
        "email": "person@example.com",
        "email_verified": true,
        "name": "Fixture Person",
        "picture": "https://images.example/person.png"
    });
    if state.issuer == "https://accounts.google.com" {
        claims["hd"] = Value::String("example.com".into());
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("fixture-signing-key".into());
    let id_token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(state.private_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    Json(json!({
        "access_token": access_token,
        "expires_in": 3600,
        "scope": "openid email profile",
        "token_type": "Bearer",
        "id_token": id_token,
        "refresh_token": "fixture-refresh-token"
    }))
    .into_response()
}

async fn signed_jwks(State(state): State<SignedFixtureState>) -> Response {
    if state
        .jwks_failures_remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(state.jwks).into_response()
}

async fn signed_userinfo(headers: HeaderMap) -> Response {
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some("Bearer fixture-access-token")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({
        "sub": "fixture-subject",
        "email": "person@example.com",
        "email_verified": true,
        "name": "Fixture Person"
    }))
    .into_response()
}

async fn setup_signed_profile(
    profile: RelayProfile,
    required_id_token_claims: HashMap<String, String>,
) -> (
    Router,
    SignedFixtureState,
    tokio::task::JoinHandle<()>,
    String,
    ClientAuth,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let issuer = match profile {
        RelayProfile::Google => "https://accounts.google.com".into(),
        RelayProfile::Cognito => base.to_string().trim_end_matches('/').into(),
    };
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "fixture-signing-key",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())
        }]
    });
    let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let fixture = SignedFixtureState {
        base: base.clone(),
        issuer,
        private_pem: Arc::new(private_pem),
        jwks,
        jwks_failures_remaining: Arc::new(AtomicUsize::new(0)),
        nonce: Arc::new(StdMutex::new(None)),
        authorize: Arc::new(StdMutex::new(Vec::new())),
    };
    let idp = Router::new()
        .route("/.well-known/openid-configuration", get(signed_discovery))
        .route("/authorize", get(signed_authorize))
        .route("/token", post(signed_token))
        .route("/jwks", get(signed_jwks))
        .route("/userinfo", get(signed_userinfo))
        .with_state(fixture.clone());
    let task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let (redirect_uri, client_auth) = match profile {
        RelayProfile::Google => ("https://app.example/callback", ClientAuth::Public),
        RelayProfile::Cognito => (
            "https://cognito.example/oauth2/idpresponse",
            ClientAuth::ClientSecret {
                client_id: "upstream-client".into(),
                client_secret: SecretString::new("upstream-secret"),
            },
        ),
    };
    let key = ResourceKey::new("profile").unwrap();
    let upstream = Arc::new(Upstream {
        key: key.clone(),
        issuer_url: Url::parse(&fixture.issuer).unwrap(),
        authorization_endpoint: Some(base.join("authorize").unwrap()),
        token_endpoint: Some(base.join("token").unwrap()),
        jwks_uri: Some(base.join("jwks").unwrap()),
        client_id: "upstream-client".into(),
        client_secret: SecretString::new("upstream-secret"),
    });
    let relay = Arc::new(Relay {
        key: key.clone(),
        upstream: key.clone(),
        client_auth: client_auth.clone(),
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        allowed_scopes: Some(vec!["openid".into(), "email".into(), "profile".into()]),
        required_id_token_claims,
        redirect_policy: vec![RedirectMatcher::uri(redirect_uri).unwrap()],
    });
    let mut resources = ProviderSnapshot::default();
    resources.upstreams.insert(key.clone(), upstream);
    resources.relays.insert(key, relay);
    let app = router(
        Arc::new(resources),
        RelayConfig {
            public_url: Url::parse("https://relay.example/").unwrap(),
            sealer: Arc::new(XChaChaSealer::new(&[8_u8; 32], None).unwrap()),
            replay_cache: Some(Arc::new(MemoryReplayCache::default())),
            http: reqwest::Client::new(),
            allow_localhost_loopback: false,
        },
        KeyStrategy::SingleSegment,
    );
    (app, fixture, task, redirect_uri.into(), client_auth)
}

async fn setup(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
) -> (Router, Arc<XChaChaSealer>, tokio::task::JoinHandle<()>) {
    let (app, sealer, task, _) =
        setup_with_capture(key, auth, strategy, None, EndpointConfiguration::Discovered).await;
    (app, sealer, task)
}

async fn setup_with_capture(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
    allowed_scopes: Option<Vec<String>>,
    endpoint_configuration: EndpointConfiguration,
) -> (
    Router,
    Arc<XChaChaSealer>,
    tokio::task::JoinHandle<()>,
    MockCapture,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = Url::parse(&format!("http://{address}/")).unwrap();
    let capture = MockCapture::default();
    let idp = Router::new()
        .route("/.well-known/openid-configuration", get(mock_discovery))
        .route("/authorize", get(mock_authorize))
        .route("/token", post(mock_token))
        .route("/jwks", get(mock_jwks))
        .with_state(MockIdpState {
            base: base.clone(),
            capture: capture.clone(),
        });
    let task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });

    let key = ResourceKey::new(key).unwrap();
    let authorization_endpoint =
        (!matches!(endpoint_configuration, EndpointConfiguration::Discovered))
            .then(|| base.join("authorize").unwrap());
    let token_endpoint = authorization_endpoint
        .as_ref()
        .map(|_| base.join("token").unwrap());
    let jwks_uri = matches!(endpoint_configuration, EndpointConfiguration::Explicit)
        .then(|| base.join("jwks").unwrap());
    let upstream = Arc::new(Upstream {
        key: key.clone(),
        issuer_url: base,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        client_id: "upstream-client".into(),
        client_secret: SecretString::new("upstream-secret"),
    });
    let relay = Arc::new(Relay {
        key: key.clone(),
        upstream: key.clone(),
        client_auth: auth,
        scopes: vec!["openid".into(), "email".into()],
        allowed_scopes,
        required_id_token_claims: HashMap::new(),
        redirect_policy: vec![
            RedirectMatcher::uri("https://app.example/callback").unwrap(),
            RedirectMatcher::uri("https://app.example/callback?channel=stable&next=%2Fhome")
                .unwrap(),
        ],
    });
    let mut resources = ProviderSnapshot::default();
    resources.upstreams.insert(key.clone(), upstream);
    resources.relays.insert(key, relay);
    let sealer = Arc::new(XChaChaSealer::new(&[7_u8; 32], None).unwrap());
    let app = router(
        Arc::new(resources),
        RelayConfig {
            public_url: Url::parse("https://relay.example/").unwrap(),
            sealer: sealer.clone(),
            replay_cache: Some(Arc::new(MemoryReplayCache::default())),
            http: reqwest::Client::new(),
            allow_localhost_loopback: false,
        },
        strategy,
    );
    (app, sealer, task, capture)
}

async fn response_body(response: Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn relays_sharing_an_upstream_use_one_provider_callback() {
    let upstream_key = ResourceKey::new("google").unwrap();
    let upstream = Arc::new(Upstream {
        key: upstream_key.clone(),
        issuer_url: Url::parse("https://issuer.example").unwrap(),
        authorization_endpoint: Some(Url::parse("https://issuer.example/authorize").unwrap()),
        token_endpoint: Some(Url::parse("https://issuer.example/token").unwrap()),
        jwks_uri: None,
        client_id: "upstream-client".into(),
        client_secret: SecretString::new("upstream-secret"),
    });
    let mut resources = ProviderSnapshot::default();
    resources.upstreams.insert(upstream_key.clone(), upstream);
    for name in ["pool-a", "pool-b"] {
        let key = ResourceKey::new(name).unwrap();
        resources.relays.insert(
            key.clone(),
            Arc::new(Relay {
                key,
                upstream: upstream_key.clone(),
                client_auth: ClientAuth::Public,
                scopes: vec!["openid".into()],
                allowed_scopes: None,
                required_id_token_claims: HashMap::new(),
                redirect_policy: vec![
                    RedirectMatcher::uri("https://app.example/callback").unwrap(),
                ],
            }),
        );
    }
    let app = router(
        Arc::new(resources),
        RelayConfig {
            public_url: Url::parse("https://relay.example/custom/base").unwrap(),
            sealer: Arc::new(XChaChaSealer::new(&[9_u8; 32], None).unwrap()),
            replay_cache: None,
            http: reqwest::Client::new(),
            allow_localhost_loopback: false,
        },
        KeyStrategy::SingleSegment,
    );
    let challenge = pkce_challenge("shared-upstream-callback-test-verifier-with-enough-characters");

    for relay in ["pool-a", "pool-b"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/custom/base/relay/{relay}/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(
            location
                .query_pairs()
                .find(|(name, _)| name == "redirect_uri")
                .unwrap()
                .1,
            "https://relay.example/custom/base/upstream/google/callback"
        );
    }
}

async fn authorization_code(app: &Router, path_key: &str, challenge: Option<&str>) -> String {
    let mut uri = format!(
        "/relay/{path_key}/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=app-state"
    );
    if let Some(challenge) = challenge {
        uri.push_str("&code_challenge=");
        uri.push_str(challenge);
        uri.push_str("&code_challenge_method=S256");
    }
    let authorize = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::FOUND);
    let upstream_location = authorize.headers()[header::LOCATION].to_str().unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let upstream = client.get(upstream_location).send().await.unwrap();
    assert_eq!(upstream.status(), StatusCode::FOUND);
    let callback = Url::parse(upstream.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let local_callback = format!("{}?{}", callback.path(), callback.query().unwrap());
    let callback_response = app
        .clone()
        .oneshot(Request::get(local_callback).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(callback_response.status(), StatusCode::FOUND);
    let app_redirect = Url::parse(
        callback_response.headers()[header::LOCATION]
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        app_redirect
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1,
        "app-state"
    );
    assert!(app_redirect
        .query_pairs()
        .any(|(name, value)| name == "session_state" && value == "upstream-session"));
    assert!(app_redirect.query_pairs().any(|(name, _)| name == "iss"));
    app_redirect
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned()
}

async fn post_token(app: &Router, path_key: &str, form: &str) -> Response {
    app.clone()
        .oneshot(
            Request::post(format!("/relay/{path_key}/token"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, "https://app.example")
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn public_pkce_flow_preserves_upstream_response_and_rejects_replay() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let verifier = "a-public-verifier-with-enough-entropy-123456789";
    let challenge = pkce_challenge(verifier);
    let code = authorization_code(&app, "google", Some(&challenge)).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap();
    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.oauth-token+json"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.example"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(String::from_utf8(response_body(response).await)
        .unwrap()
        .contains("access"));
    let replay = post_token(&app, "google", &form).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(String::from_utf8(response_body(replay).await)
        .unwrap()
        .contains("already used"));
    task.abort();
}

#[tokio::test]
async fn public_client_id_is_identification_not_authentication() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let verifier = "a-public-verifier-with-enough-entropy-123456789";
    let code = authorization_code(&app, "google", Some(&pkce_challenge(verifier))).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
        ("client_id", "public-application"),
    ])
    .unwrap();

    assert_eq!(
        post_token(&app, "google", &form).await.status(),
        StatusCode::CREATED
    );
    task.abort();
}

#[tokio::test]
async fn public_relay_rejects_client_authentication_credentials() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let requests = [
        "grant_type=refresh_token&refresh_token=refresh&client_id=public-application&client_secret=",
        "grant_type=refresh_token&refresh_token=refresh&client_id=public-application&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=assertion",
    ];

    for form in requests {
        let response = post_token(&app, "google", form).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(body["error"], "invalid_client");
    }
    task.abort();
}

#[tokio::test]
async fn confidential_flow_and_refresh_authenticate_client_secret() {
    let auth = ClientAuth::ClientSecret {
        client_id: "application".into(),
        client_secret: SecretString::new("application-secret"),
    };
    let (app, _, task, capture) = setup_with_capture(
        "github",
        auth,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
    )
    .await;
    let code = authorization_code(&app, "github", None).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("client_id", "application"),
        ("client_secret", "application-secret"),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "github", &form).await.status(),
        StatusCode::CREATED
    );
    let refresh = "grant_type=refresh_token&refresh_token=refresh&client_id=application&client_secret=application-secret&client_assertion=downstream-only&scope=openid&resource=one&resource=two";
    let response = post_token(&app, "github", refresh).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.oauth-refresh+json"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let upstream_refresh = capture.token.lock().unwrap().last().unwrap().clone();
    assert!(upstream_refresh
        .iter()
        .any(|pair| pair == &("client_id".into(), "upstream-client".into())));
    assert!(upstream_refresh
        .iter()
        .any(|pair| pair == &("client_secret".into(), "upstream-secret".into())));
    assert!(!upstream_refresh
        .iter()
        .any(|(name, value)| name == "client_assertion" || value == "application-secret"));
    assert_eq!(
        upstream_refresh
            .iter()
            .filter(|(name, _)| name == "resource")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    let invalid = refresh.replace("application-secret", "wrong");
    assert_eq!(
        post_token(&app, "github", &invalid).await.status(),
        StatusCode::UNAUTHORIZED
    );
    task.abort();
}

#[tokio::test]
async fn expired_code_and_invalid_redirect_are_rejected() {
    let (app, sealer, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let invalid = app.clone().oneshot(
        Request::get("/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example.evil.test%2Fcb&code_challenge=x&code_challenge_method=S256")
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let expired = CodeEnvelope {
        relay_key: "google".into(),
        envelope_id: [9; 16],
        issued_at: unix_now() - CODE_TTL - 1,
        redirect_uri: "https://app.example/callback".into(),
        client_code_challenge: Some(pkce_challenge("verifier")),
        id_token_nonce: None,
        upstream_response: StoredResponse {
            status: 200,
            content_type: None,
            body: vec![],
        },
    };
    let code = sealer
        .seal(&postcard::to_stdvec(&expired).unwrap(), b"google")
        .unwrap();
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", "verifier"),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "google", &form).await.status(),
        StatusCode::BAD_REQUEST
    );

    let expired_flow = FlowEnvelope {
        relay_key: "google".into(),
        app_redirect_uri: "https://app.example/callback".into(),
        app_state: None,
        upstream_pkce_verifier: "upstream-verifier".into(),
        client_code_challenge: Some(pkce_challenge("verifier")),
        client_code_challenge_method: Some("S256".into()),
        id_token_nonce: None,
        issued_at: unix_now() - FLOW_TTL - 1,
        nonce: [4; 16],
    };
    let state = sealer
        .seal(&postcard::to_stdvec(&expired_flow).unwrap(), b"google")
        .unwrap();
    let callback = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/upstream/google/callback?code=upstream&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);

    let disallowed_flow = FlowEnvelope {
        relay_key: "google".into(),
        app_redirect_uri: "https://app.example/other".into(),
        app_state: None,
        upstream_pkce_verifier: "upstream-verifier".into(),
        client_code_challenge: Some(pkce_challenge("verifier")),
        client_code_challenge_method: Some("S256".into()),
        id_token_nonce: None,
        issued_at: unix_now(),
        nonce: [5; 16],
    };
    let state = sealer
        .seal(&postcard::to_stdvec(&disallowed_flow).unwrap(), b"google")
        .unwrap();
    let callback = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/upstream/google/callback?error=access_denied&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn upstream_authorization_errors_relay_only_to_validated_redirect() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let challenge = pkce_challenge("an-application-verifier-with-at-least-forty-three-characters");
    let authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=application&code_challenge={challenge}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let upstream = Url::parse(authorize.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let state = upstream
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let response = app
        .oneshot(
            Request::get(format!(
                "/upstream/google/callback?error=access_denied&error_description=declined&error_uri=https%3A%2F%2Fissuer.example%2Ferrors%2Fdenied&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(redirect.host_str(), Some("app.example"));
    assert!(redirect.query().unwrap().contains("error=access_denied"));
    assert!(redirect.query().unwrap().contains("error_uri="));
    assert!(redirect.query().unwrap().contains("state=application"));
    task.abort();
}

#[tokio::test]
async fn exact_redirect_query_is_matched_before_results_are_appended() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let challenge = pkce_challenge("an-application-verifier-with-at-least-forty-three-characters");

    for uri in [
        format!(
            "/relay/google/authorize?code_challenge={challenge}&code_challenge_method=S256"
        ),
        format!(
            "/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%3Fchannel%3Dother&code_challenge={challenge}&code_challenge_method=S256"
        ),
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%3Fchannel%3Dstable%26next%3D%252Fhome&state=application&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::FOUND);
    let upstream = Url::parse(authorize.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let state = upstream
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let response = app
        .oneshot(
            Request::get(format!(
                "/upstream/google/callback?error=access_denied&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with(
        "https://app.example/callback?channel=stable&next=%2Fhome&error=access_denied"
    ));
    let redirect = Url::parse(location).unwrap();
    let pairs: Vec<_> = redirect.query_pairs().into_owned().collect();
    assert_eq!(
        pairs,
        [
            ("channel".into(), "stable".into()),
            ("next".into(), "/home".into()),
            ("error".into(), "access_denied".into()),
            ("state".into(), "application".into()),
        ]
    );
    task.abort();
}

#[tokio::test]
async fn authorization_relay_preserves_extensions_and_applies_scope_policy() {
    let verifier = "relay-verifier-with-at-least-forty-three-characters";
    let challenge = pkce_challenge(verifier);
    let (app, _, task, _) = setup_with_capture(
        "relay",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        Some(vec!["openid".into(), "email".into()]),
        EndpointConfiguration::Discovered,
    )
    .await;
    let request = format!(
        "/relay/relay/authorize?client_id=downstream&response_type=code&response_mode=query&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=downstream-state&code_challenge={challenge}&code_challenge_method=S256&scope=email%20openid&nonce=nonce-value&prompt=consent&login_hint=user%40example.com&access_type=offline&resource=one&resource=two"
    );
    let response = app
        .clone()
        .oneshot(Request::get(request).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let upstream = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let pairs: Vec<_> = upstream.query_pairs().into_owned().collect();
    let values = |name: &str| {
        pairs
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(values("client_id"), ["upstream-client"]);
    assert_eq!(values("response_type"), ["code"]);
    assert_eq!(values("scope"), ["email openid"]);
    assert_eq!(values("nonce"), ["nonce-value"]);
    assert_eq!(values("prompt"), ["consent"]);
    assert_eq!(values("login_hint"), ["user@example.com"]);
    assert_eq!(values("access_type"), ["offline"]);
    assert_eq!(values("resource"), ["one", "two"]);
    assert_ne!(values("state"), ["downstream-state"]);
    assert_ne!(values("code_challenge"), [challenge.as_str()]);

    for invalid in [
        format!(
            "/relay/relay/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256&scope=admin"
        ),
        format!(
            "/relay/relay/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256&request=opaque"
        ),
        format!(
            "/relay/relay/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256&response_mode=form_post"
        ),
        format!(
            "/relay/relay/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256&nonce=one&nonce=two"
        ),
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(invalid).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    task.abort();
}

fn validate_fixture_id_token(
    token: &str,
    jwks: &Value,
    issuer: &str,
    nonce: &str,
    access_token: &str,
) -> Result<Value, String> {
    let header = decode_header(token).map_err(|error| error.to_string())?;
    let set: JwkSet = serde_json::from_value(jwks.clone()).map_err(|error| error.to_string())?;
    let key = set
        .keys
        .iter()
        .find(|key| key.common.key_id.as_deref() == header.kid.as_deref())
        .ok_or("unknown kid")?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&["upstream-client"]);
    let claims = decode::<Value>(
        token,
        &DecodingKey::from_jwk(key).map_err(|error| error.to_string())?,
        &validation,
    )
    .map_err(|error| error.to_string())?
    .claims;
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err("nonce mismatch".into());
    }
    let expected_at_hash = URL_SAFE_NO_PAD.encode(&Sha256::digest(access_token.as_bytes())[..16]);
    if claims.get("at_hash").and_then(Value::as_str) != Some(expected_at_hash.as_str()) {
        return Err("at_hash mismatch".into());
    }
    Ok(claims)
}

async fn signed_authorization_code(app: &Router, redirect_uri: &str) -> (String, String) {
    let verifier = "required-claims-verifier-with-at-least-forty-three-characters".to_owned();
    let mut authorize = Url::parse("https://relay.example/relay/profile/authorize").unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", "required-claims-state")
        .append_pair("scope", "openid email profile")
        .append_pair("nonce", "required-claims-nonce")
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256");
    let relay_authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "{}?{}",
                authorize.path(),
                authorize.query().unwrap()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let upstream = client
        .get(
            relay_authorize.headers()[header::LOCATION]
                .to_str()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let callback = Url::parse(upstream.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let relay_callback = app
        .clone()
        .oneshot(
            Request::get(format!("{}?{}", callback.path(), callback.query().unwrap()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let application =
        Url::parse(relay_callback.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let code = application
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    (code, verifier)
}

#[tokio::test]
async fn required_id_token_claims_accept_exact_strings_and_reject_missing_or_mismatched_claims() {
    for (required, accepted) in [
        (HashMap::from([("hd".into(), "example.com".into())]), true),
        (
            HashMap::from([("department".into(), "engineering".into())]),
            false,
        ),
        (
            HashMap::from([("hd".into(), "other.example".into())]),
            false,
        ),
    ] {
        let (app, _, task, redirect_uri, _) =
            setup_signed_profile(RelayProfile::Google, required).await;
        let (code, verifier) = signed_authorization_code(&app, &redirect_uri).await;
        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .unwrap();
        let response = post_token(&app, "profile", &form).await;

        if accepted {
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
            assert!(body.get("id_token").is_some());
        } else {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::PRAGMA], "no-cache");
            let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
            assert_eq!(body["error"], "invalid_grant");
            assert_eq!(
                body["error_description"],
                "Identity does not satisfy required ID-token claims."
            );
            assert!(!body.to_string().contains("department"));
            assert!(!body.to_string().contains("other.example"));

            let replay = post_token(&app, "profile", &form).await;
            assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
            let replay_body: Value = serde_json::from_slice(&response_body(replay).await).unwrap();
            assert_eq!(replay_body["error"], "invalid_grant");
            assert_eq!(replay_body["error_description"], "code was already used");
        }
        task.abort();
    }
}

#[tokio::test]
async fn transient_id_token_validation_failure_does_not_consume_the_relay_code() {
    let (app, fixture, task, redirect_uri, _) = setup_signed_profile(
        RelayProfile::Google,
        HashMap::from([("hd".into(), "example.com".into())]),
    )
    .await;
    fixture.jwks_failures_remaining.store(1, Ordering::SeqCst);
    let (code, verifier) = signed_authorization_code(&app, &redirect_uri).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier.as_str()),
    ])
    .unwrap();

    let unavailable = post_token(&app, "profile", &form).await;
    assert_eq!(unavailable.status(), StatusCode::BAD_GATEWAY);
    let unavailable_body: Value =
        serde_json::from_slice(&response_body(unavailable).await).unwrap();
    assert_eq!(unavailable_body["error"], "server_error");

    let retry = post_token(&app, "profile", &form).await;
    assert_eq!(retry.status(), StatusCode::OK);

    let replay = post_token(&app, "profile", &form).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let replay_body: Value = serde_json::from_slice(&response_body(replay).await).unwrap();
    assert_eq!(replay_body["error_description"], "code was already used");
    task.abort();
}

async fn run_signed_relay_profile(profile: RelayProfile) {
    let (app, fixture, task, redirect_uri, client_auth) =
        setup_signed_profile(profile, HashMap::new()).await;
    let nonce = "relying-party-nonce";
    let verifier = "profile-verifier-with-at-least-forty-three-characters";
    let mut authorize = Url::parse("https://relay.example/relay/profile/authorize").unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("client_id", "upstream-client")
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", "relying-party-state")
        .append_pair("scope", "openid email profile")
        .append_pair("nonce", nonce);
    if profile == RelayProfile::Google {
        authorize
            .query_pairs_mut()
            .append_pair("code_challenge", &pkce_challenge(verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent")
            .append_pair("login_hint", "person@example.com")
            .append_pair("hd", "example.com");
    }
    let relay_authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "{}?{}",
                authorize.path(),
                authorize.query().unwrap()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(relay_authorize.status(), StatusCode::FOUND);
    let upstream = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(
            relay_authorize.headers()[header::LOCATION]
                .to_str()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upstream.status(), StatusCode::FOUND);
    let callback = Url::parse(upstream.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let relay_callback = app
        .clone()
        .oneshot(
            Request::get(format!("{}?{}", callback.path(), callback.query().unwrap()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(relay_callback.status(), StatusCode::FOUND);
    let application =
        Url::parse(relay_callback.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        application
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1,
        "relying-party-state"
    );
    let code = application
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let mut token_form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    match client_auth {
        ClientAuth::UpstreamClient => {
            token_form.push(("client_id", "upstream-client"));
            token_form.push(("client_secret", "upstream-secret"));
        }
        ClientAuth::Public => token_form.push(("code_verifier", verifier)),
        ClientAuth::ClientSecret { .. } => {
            token_form.push(("client_id", "upstream-client"));
            token_form.push(("client_secret", "upstream-secret"));
        }
        ClientAuth::PrivateKeyJwt { .. } => unreachable!(),
    }
    let token = post_token(
        &app,
        "profile",
        &serde_urlencoded::to_string(token_form).unwrap(),
    )
    .await;
    assert_eq!(token.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response_body(token).await).unwrap();
    let access_token = body["access_token"].as_str().unwrap();
    let claims = validate_fixture_id_token(
        body["id_token"].as_str().unwrap(),
        &fixture.jwks,
        &fixture.issuer,
        nonce,
        access_token,
    )
    .unwrap();
    assert_eq!(claims["email"], "person@example.com");
    assert!(validate_fixture_id_token(
        body["id_token"].as_str().unwrap(),
        &fixture.jwks,
        &fixture.issuer,
        "wrong-nonce",
        access_token,
    )
    .is_err());

    if profile == RelayProfile::Google {
        {
            let authorize = fixture.authorize.lock().unwrap();
            for expected in [
                ("access_type", "offline"),
                ("prompt", "consent"),
                ("login_hint", "person@example.com"),
                ("hd", "example.com"),
            ] {
                assert!(authorize
                    .iter()
                    .any(|(name, value)| name == expected.0 && value == expected.1));
            }
        }
        assert_eq!(claims["iss"], "https://accounts.google.com");
        assert_eq!(claims["hd"], "example.com");
        let refresh = post_token(
            &app,
            "profile",
            "grant_type=refresh_token&refresh_token=fixture-refresh-token&scope=openid%20email&resource=google-resource",
        )
        .await;
        let refreshed: Value = serde_json::from_slice(&response_body(refresh).await).unwrap();
        assert_eq!(refreshed["access_token"], "fixture-refreshed-access-token");
        assert!(refreshed.get("refresh_token").is_none());
        let invalid_scope = post_token(
            &app,
            "profile",
            "grant_type=refresh_token&refresh_token=fixture-refresh-token&scope=admin",
        )
        .await;
        assert_eq!(invalid_scope.status(), StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(response_body(invalid_scope).await)
            .unwrap()
            .contains("invalid_scope"));
    } else {
        let userinfo = reqwest::Client::new()
            .get(fixture.base.join("userinfo").unwrap())
            .bearer_auth(access_token)
            .send()
            .await
            .unwrap();
        assert_eq!(userinfo.status(), StatusCode::OK);
        let user: Value = userinfo.json().await.unwrap();
        assert_eq!(user["sub"], claims["sub"]);
        assert_eq!(user["email"], claims["email"]);
    }
    task.abort();
}

#[tokio::test]
async fn google_shaped_relay_preserves_provider_parameters_and_tokens() {
    run_signed_relay_profile(RelayProfile::Google).await;
}

#[tokio::test]
async fn cognito_shaped_relying_party_uses_manual_trust_endpoints() {
    run_signed_relay_profile(RelayProfile::Cognito).await;
}

#[tokio::test]
async fn discovery_preserves_upstream_trust_and_rewrites_relay_endpoints() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/relay/google/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    let issuer = value["issuer"].as_str().unwrap();
    assert!(issuer.starts_with("http://127.0.0.1:"));
    assert_eq!(
        value["authorization_endpoint"],
        "https://relay.example/relay/google/authorize"
    );
    assert_eq!(
        value["token_endpoint"],
        "https://relay.example/relay/google/token"
    );
    assert_eq!(value["jwks_uri"], format!("{issuer}jwks"));
    assert_eq!(value["custom_field"], "preserved");
    let jwks = app
        .oneshot(
            Request::get("/relay/google/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    task.abort();
}

#[tokio::test]
async fn explicit_endpoints_produce_transparent_relay_metadata() {
    let (app, _, task, _) = setup_with_capture(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Explicit,
    )
    .await;
    let response = app
        .oneshot(
            Request::get("/relay/google/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    let issuer = value["issuer"].as_str().unwrap();
    assert!(issuer.starts_with("http://127.0.0.1:"));
    assert_eq!(
        value["authorization_endpoint"],
        "https://relay.example/relay/google/authorize"
    );
    assert_eq!(
        value["token_endpoint"],
        "https://relay.example/relay/google/token"
    );
    assert_eq!(value["jwks_uri"], format!("{issuer}/jwks"));
    task.abort();
}

#[tokio::test]
async fn discovery_supplies_jwks_when_other_endpoints_are_explicit() {
    let (app, _, task, _) = setup_with_capture(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::ExplicitWithoutJwks,
    )
    .await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/relay/google/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    let issuer = value["issuer"].as_str().unwrap();
    assert_eq!(value["jwks_uri"], format!("{issuer}jwks"));

    let jwks = app
        .oneshot(
            Request::get("/relay/google/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&response_body(jwks).await).unwrap(),
        json!({ "keys": [] })
    );
    task.abort();
}

#[tokio::test]
async fn token_preflight_reflects_only_an_allowed_origin() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let allowed = app
        .clone()
        .oneshot(
            Request::options("/relay/google/token")
                .header(header::ORIGIN, "https://app.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST, OPTIONS"
    );
    let denied = app
        .oneshot(
            Request::options("/relay/google/token")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    task.abort();
}

#[tokio::test]
async fn two_segment_embedding_runs_the_same_flow() {
    let (app, _, task) = setup(
        "project/google",
        ClientAuth::Public,
        KeyStrategy::TwoSegment,
    )
    .await;
    let verifier = "two-segment-verifier-with-at-least-forty-three-characters";
    let code = authorization_code(&app, "project/google", Some(&pkce_challenge(verifier))).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "project/google", &form).await.status(),
        StatusCode::CREATED
    );
    task.abort();
}

#[tokio::test]
async fn private_key_jwt_authenticates_a_signed_assertion() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "application-key",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())
        }]
    });
    let auth = ClientAuth::PrivateKeyJwt {
        require_single_use: true,
        client_id: "jwt-application".into(),
        issuer: None,
        subject: None,
        audience: None,
        jwks: Some(ClientJwks::Inline(jwks)),
    };
    let (app, _, task) = setup("jwt", auth, KeyStrategy::SingleSegment).await;
    let code = authorization_code(&app, "jwt", None).await;
    let claims = json!({
        "iss": "jwt-application",
        "sub": "jwt-application",
        "aud": "https://relay.example/relay/jwt/token",
        "exp": unix_now() + 60,
        "iat": unix_now(),
        "jti": "unique-assertion"
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("application-key".into());
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let assertion = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("client_id", "jwt-application"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "jwt", &form).await.status(),
        StatusCode::CREATED
    );
    let replay = post_token(&app, "jwt", &form).await;
    let body: Value = serde_json::from_slice(&response_body(replay).await).unwrap();
    assert_eq!(body["error"], "invalid_client");
    task.abort();
}

#[tokio::test]
async fn workload_jwt_enforces_identity_audience_and_validity_for_every_key_source() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let signing_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let jwks = json!({"keys": [{"kty":"RSA", "kid":"cluster-key", "alg":"RS256",
        "n":URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
        "e":URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())}]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/cluster", listener.local_addr().unwrap());
    let doc = json!({"issuer":issuer, "jwks_uri":format!("{issuer}/keys")});
    let discovery_hits = Arc::new(AtomicUsize::new(0));
    let hits = discovery_hits.clone();
    let keys = jwks.clone();
    let idp = Router::new()
        .route(
            "/cluster/.well-known/openid-configuration",
            get(move || {
                let doc = doc.clone();
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(doc)
                }
            }),
        )
        .route(
            "/cluster/keys",
            get(move || {
                let keys = keys.clone();
                async move { Json(keys) }
            }),
        );
    let issuer_task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("cluster-key".into());
    let claims = json!({"iss":issuer, "sub":"system:serviceaccount:workloads:worker",
        "aud":["https://relay.example/relay/jwt/token"], "exp":unix_now()+3600,
        "iat":unix_now(), "nbf":unix_now(), "jti":"reusable-projected-token"});
    for (source, configured_audience) in [
        (Some(ClientJwks::Inline(jwks)), None),
        (
            Some(ClientJwks::Url(
                Url::parse(&format!("{issuer}/keys")).unwrap(),
            )),
            Some("api://oauthrelay"),
        ),
        (None, Some("api://oauthrelay")),
    ] {
        let audience = configured_audience.unwrap_or("https://relay.example/relay/jwt/token");
        let mut claims = claims.clone();
        claims["aud"] = json!([audience]);
        let auth = ClientAuth::PrivateKeyJwt {
            require_single_use: false,
            client_id: "worker-client".into(),
            issuer: Some(issuer.clone()),
            subject: Some("system:serviceaccount:workloads:worker".into()),
            audience: configured_audience.map(str::to_owned),
            jwks: source,
        };
        let (app, _, task, capture) = setup_with_capture(
            "jwt",
            auth,
            KeyStrategy::SingleSegment,
            None,
            EndpointConfiguration::Explicit,
        )
        .await;
        let valid = encode(&header, &claims, &signing_key).unwrap();
        let code = authorization_code(&app, "jwt", None).await;
        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://app.example/callback"),
            ("client_id", "worker-client"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", valid.as_str()),
        ])
        .unwrap();
        assert_eq!(
            post_token(&app, "jwt", &form).await.status(),
            StatusCode::CREATED
        );
        let refresh_form = |assertion: &str, client_id: &str| {
            serde_urlencoded::to_string([
                ("grant_type", "refresh_token"),
                ("refresh_token", "upstream-refresh"),
                ("client_id", client_id),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion),
            ])
            .unwrap()
        };
        // Projected tokens remain usable across requests until the kubelet rotates them.
        for _ in 0..2 {
            assert_eq!(
                post_token(&app, "jwt", &refresh_form(&valid, "worker-client"))
                    .await
                    .status(),
                StatusCode::ACCEPTED
            );
        }
        for aud in [json!(audience), json!(["another-audience", audience])] {
            let mut claims = claims.clone();
            claims["aud"] = aud;
            let assertion = encode(&header, &claims, &signing_key).unwrap();
            assert_eq!(
                post_token(&app, "jwt", &refresh_form(&assertion, "worker-client"))
                    .await
                    .status(),
                StatusCode::ACCEPTED
            );
        }
        let forwarded = capture.token.lock().unwrap().len();
        for (claim, value) in [
            (
                "aud",
                json!(if configured_audience.is_some() {
                    "https://relay.example/relay/jwt/token"
                } else {
                    "api://oauthrelay"
                }),
            ),
            ("aud", json!("")),
            ("aud", json!([])),
            ("aud", Value::Null),
            ("iss", json!("https://another-cluster.example")),
            ("iss", json!(format!("{issuer}/"))),
            ("sub", json!("system:serviceaccount:other:worker")),
            ("sub", json!("system:serviceaccount:workloads:other")),
            ("sub", json!(["system:serviceaccount:workloads:worker"])),
            ("aud", json!(["https://kubernetes.default.svc"])),
            ("aud", json!("https://relay.example/relay/other/token")),
            ("exp", json!(unix_now() - 120)),
            ("exp", json!("tomorrow")),
            ("nbf", json!(unix_now() + 120)),
            ("nbf", json!("tomorrow")),
            ("iat", json!(unix_now() + 120)),
            ("iat", json!("now")),
        ] {
            let mut invalid = claims.clone();
            invalid[claim] = value;
            let assertion = encode(&header, &invalid, &signing_key).unwrap();
            assert_eq!(
                post_token(&app, "jwt", &refresh_form(&assertion, "worker-client"))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED,
                "invalid {claim}: {invalid}"
            );
        }
        for claim in ["iss", "sub", "aud", "exp"] {
            let mut invalid = claims.clone();
            invalid.as_object_mut().unwrap().remove(claim);
            let assertion = encode(&header, &invalid, &signing_key).unwrap();
            assert_eq!(
                post_token(&app, "jwt", &refresh_form(&assertion, "worker-client"))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED,
                "missing {claim}"
            );
        }
        assert_eq!(
            post_token(&app, "jwt", &refresh_form(&valid, "other-client"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut unknown_key = header.clone();
        unknown_key.kid = Some("unknown-key".into());
        let assertion = encode(&unknown_key, &claims, &signing_key).unwrap();
        assert_eq!(
            post_token(&app, "jwt", &refresh_form(&assertion, "worker-client"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let assertion = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"untrusted"),
        )
        .unwrap();
        assert_eq!(
            post_token(&app, "jwt", &refresh_form(&assertion, "worker-client"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut parts: Vec<_> = valid.split('.').map(str::to_owned).collect();
        let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
        parts[2].replace_range(..1, replacement);
        assert_eq!(
            post_token(
                &app,
                "jwt",
                &refresh_form(&parts.join("."), "worker-client")
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            capture.token.lock().unwrap().len(),
            forwarded,
            "rejected assertions never reach the upstream"
        );
        task.abort();
    }
    assert_eq!(
        discovery_hits.load(Ordering::SeqCst),
        1,
        "only issuer discovery fetches metadata, cached across requests"
    );
    issuer_task.abort();
}

#[tokio::test]
async fn workload_jwt_rejects_invalid_discovery_metadata() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/cluster", listener.local_addr().unwrap());
    let document = Arc::new(StdMutex::new(Value::Null));
    let response = document.clone();
    let idp = Router::new().route(
        "/cluster/.well-known/openid-configuration",
        get(move || {
            let response = response.clone();
            async move { Json(response.lock().unwrap().clone()) }
        }),
    );
    let issuer_task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let claims = json!({"iss":issuer,"sub":"worker","aud":"https://relay.example/relay/jwt/token","exp":unix_now()+300});
    let assertion = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    for metadata in [
        json!({"issuer":"https://untrusted.example","jwks_uri":format!("{issuer}/keys")}),
        json!({"issuer":format!("{issuer}/"),"jwks_uri":format!("{issuer}/keys")}),
        json!({"jwks_uri":format!("{issuer}/keys")}),
        json!({"issuer":issuer}),
        json!({"issuer":issuer,"jwks_uri":"http://untrusted.example/keys"}),
        json!({"issuer":issuer,"jwks_uri":"file:///keys"}),
        json!({"issuer":issuer,"jwks_uri":format!("{issuer}/missing-keys")}),
    ] {
        *document.lock().unwrap() = metadata.clone();
        let (app, _, task) = setup(
            "jwt",
            ClientAuth::PrivateKeyJwt {
                require_single_use: false,
                client_id: "worker".into(),
                issuer: Some(issuer.clone()),
                subject: None,
                audience: None,
                jwks: None,
            },
            KeyStrategy::SingleSegment,
        )
        .await;
        let form = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", "refresh"),
            ("client_id", "worker"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
        ])
        .unwrap();
        assert_eq!(
            post_token(&app, "jwt", &form).await.status(),
            StatusCode::UNAUTHORIZED,
            "{metadata}"
        );
        task.abort();
    }
    issuer_task.abort();
}

#[tokio::test]
async fn single_use_assertions_enforce_lifetime_and_atomic_replay_protection() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let source = ClientJwks::Inline(json!({"keys": [{"kty":"RSA",
        "n":URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
        "e":URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())}]}));
    let cache = Arc::new(MemoryReplayCache::default());
    let make_state = |replay_cache| AppState {
        resolver: Arc::new(ProviderSnapshot::default()),
        cfg: Arc::new(RelayConfig {
            public_url: "https://relay.example/".parse().unwrap(),
            sealer: Arc::new(XChaChaSealer::new(&[8; 32], None).unwrap()),
            replay_cache,
            http: reqwest::Client::new(),
            allow_localhost_loopback: false,
        }),
        keys: KeyStrategy::SingleSegment,
        cache: Arc::new(Mutex::new(HashMap::new())),
    };
    let state = make_state(Some(cache.clone() as Arc<dyn ReplayCache>));
    let other_instance = make_state(Some(cache));
    let no_cache = make_state(None);
    let now = unix_now();
    let claims = json!({"iss":"client", "sub":"client", "aud":"relay",
        "iat":now, "exp":now + 300, "jti":"request-1"});
    let sign = |claims: &Value| encode(&Header::new(Algorithm::RS256), claims, &key).unwrap();
    for (field, value) in [
        ("iat", Value::Null),
        ("jti", Value::Null),
        ("jti", json!("")),
        ("jti", json!(123)),
        ("exp", json!(now + 301)),
        ("exp", json!(now)),
        ("iat", json!(now + 120)),
        ("aud", json!("other")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        assert!(
            verify_private_key_jwt(
                &state,
                "relay",
                "client",
                "client",
                Some(&source),
                &sign(&invalid),
                true
            )
            .await
            .is_err(),
            "{field}"
        );
    }
    let assertion = sign(&claims);
    assert!(verify_private_key_jwt(
        &no_cache,
        "relay",
        "client",
        "client",
        Some(&source),
        &assertion,
        true
    )
    .await
    .is_err());
    let (first, second) = tokio::join!(
        verify_private_key_jwt(
            &state,
            "relay",
            "client",
            "client",
            Some(&source),
            &assertion,
            true
        ),
        verify_private_key_jwt(
            &other_instance,
            "relay",
            "client",
            "client",
            Some(&source),
            &assertion,
            true
        ),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let mut fresh = claims.clone();
    fresh["jti"] = json!("request-2");
    assert!(verify_private_key_jwt(
        &state,
        "relay",
        "client",
        "client",
        Some(&source),
        &sign(&fresh),
        true
    )
    .await
    .is_ok());
    // Workload assertions remain reusable without a replay cache or per-request claims.
    let mut workload = claims.clone();
    workload.as_object_mut().unwrap().remove("jti");
    workload.as_object_mut().unwrap().remove("iat");
    workload["exp"] = json!(now + 3600);
    for _ in 0..2 {
        assert!(verify_private_key_jwt(
            &no_cache,
            "relay",
            "client",
            "client",
            Some(&source),
            &sign(&workload),
            false
        )
        .await
        .is_ok());
    }
}
