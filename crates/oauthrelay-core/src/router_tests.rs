use super::*;
use crate::{
    refresh_handle::{open_handle, seal_handle},
    rotation::Rotator,
    seal::FlakySealer,
    ClientAuth, MemoryStore, ProviderSnapshot, RedirectMatcher, RefreshTokenMode, RefreshTokens,
    SecretString, TokenEndpointAuthMethod, Upstream, XChaChaSealer, DEFAULT_GRACE_PERIOD_SECONDS,
    DEFAULT_MAX_LIFETIME_SECONDS,
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
    /// The `Accept` header of every token request.
    accept: Arc<StdMutex<Vec<Option<String>>>>,
    /// The `Authorization` header of every token request.
    authorization: Arc<StdMutex<Vec<Option<String>>>>,
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
    let value_opt = |name: &str| {
        query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    };
    let mut callback = Url::parse(value("redirect_uri")).unwrap();
    callback
        .query_pairs_mut()
        .append_pair(
            "code",
            if value_opt("login_hint") == Some("no-refresh") {
                "upstream-code-no-refresh"
            } else if value_opt("login_hint") == Some("form-body") {
                "upstream-code-form"
            } else {
                "upstream-code"
            },
        )
        .append_pair("state", value("state"))
        .append_pair("iss", state.base.as_str())
        .append_pair("session_state", "upstream-session");
    found(callback.as_str())
}

async fn mock_token(
    State(state): State<MockIdpState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    state.capture.accept.lock().unwrap().push(
        headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    );
    state.capture.authorization.lock().unwrap().push(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    );
    state.capture.token.lock().unwrap().push(
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect(),
    );
    if body.contains("grant_type=refresh_token") && body.contains("refresh_token=rotating") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json;charset=UTF-8")
            .body(Body::from(
                r#"{"token_type":"Bearer","refresh_token":"rotated","access_token":"refreshed","expires_in":3600}"#,
            ))
            .unwrap();
    }
    if body.contains("grant_type=refresh_token") && body.contains("refresh_token=revoked-upstream")
    {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"error":"invalid_grant","error_description":"Token has been revoked"}"#,
            ))
            .unwrap();
    }
    if body.contains("grant_type=refresh_token") && body.contains("refresh_token=broken-upstream") {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"server_error"}"#))
            .unwrap();
    }
    if body.contains("grant_type=refresh_token") && body.contains("refresh_token=plain-json") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(
                r#"{"access_token":"plain","refresh_token":"plain-rotated"}"#,
            ))
            .unwrap();
    }
    if (body.contains("grant_type=refresh_token") && body.contains("refresh_token=form-encoded"))
        || body.contains("code=upstream-code-form")
    {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "access_token=form&refresh_token=raw-secret&token_type=Bearer",
            ))
            .unwrap();
    }
    if body.contains("grant_type=refresh_token") {
        return Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(header::CONTENT_TYPE, "application/vnd.oauth-refresh+json")
            .body(Body::from(
                r#"{"access_token":"refreshed","token_type":"Bearer"}"#,
            ))
            .unwrap();
    }
    if body.contains("code=upstream-code-no-refresh") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"access_token":"access","token_type":"Bearer"}"#,
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
    claim_overrides: Arc<StdMutex<serde_json::Map<String, Value>>>,
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
    for (name, value) in state.claim_overrides.lock().unwrap().iter() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(name);
        } else {
            claims[name] = value.clone();
        }
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
) -> SignedProfile {
    setup_signed_policy(profile, required_id_token_claims, None).await
}

type SignedProfile = (
    Router,
    SignedFixtureState,
    tokio::task::JoinHandle<()>,
    String,
    ClientAuth,
);

async fn setup_signed_policy(
    profile: RelayProfile,
    required_id_token_claims: HashMap<String, String>,
    id_token_policy: Option<crate::IdTokenPolicy>,
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
        claim_overrides: Arc::new(StdMutex::new(serde_json::Map::new())),
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
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
    });
    let relay = Arc::new(Relay {
        key: key.clone(),
        upstream: key.clone(),
        client_auth: client_auth.clone(),
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        allowed_scopes: Some(vec!["openid".into(), "email".into(), "profile".into()]),
        required_id_token_claims,
        id_token_policy,
        refresh_tokens: Default::default(),
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
            store: Some(Arc::new(MemoryStore::default())),
            http: reqwest::Client::new(),
            client_assertion_http: Default::default(),
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
    setup_with_refresh_tokens(
        key,
        auth,
        strategy,
        allowed_scopes,
        endpoint_configuration,
        RefreshTokens::default(),
    )
    .await
}

async fn setup_with_refresh_tokens(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
    allowed_scopes: Option<Vec<String>>,
    endpoint_configuration: EndpointConfiguration,
    refresh_tokens: RefreshTokens,
) -> (
    Router,
    Arc<XChaChaSealer>,
    tokio::task::JoinHandle<()>,
    MockCapture,
) {
    setup_with_store(
        key,
        auth,
        strategy,
        allowed_scopes,
        endpoint_configuration,
        refresh_tokens,
        Arc::new(MemoryStore::default()),
    )
    .await
}

async fn setup_with_store(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
    allowed_scopes: Option<Vec<String>>,
    endpoint_configuration: EndpointConfiguration,
    refresh_tokens: RefreshTokens,
    store: Arc<dyn TransientStore>,
) -> (
    Router,
    Arc<XChaChaSealer>,
    tokio::task::JoinHandle<()>,
    MockCapture,
) {
    setup_with_upstream_auth(
        key,
        auth,
        strategy,
        allowed_scopes,
        endpoint_configuration,
        refresh_tokens,
        store,
        TokenEndpointAuthMethod::ClientSecretPost,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn setup_with_upstream_auth(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
    allowed_scopes: Option<Vec<String>>,
    endpoint_configuration: EndpointConfiguration,
    refresh_tokens: RefreshTokens,
    store: Arc<dyn TransientStore>,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
) -> (
    Router,
    Arc<XChaChaSealer>,
    tokio::task::JoinHandle<()>,
    MockCapture,
) {
    let sealer = Arc::new(XChaChaSealer::new(&[7_u8; 32], None).unwrap());
    let (app, task, capture) = setup_with_sealer(
        key,
        auth,
        strategy,
        allowed_scopes,
        endpoint_configuration,
        refresh_tokens,
        store,
        token_endpoint_auth_method,
        sealer.clone(),
    )
    .await;
    (app, sealer, task, capture)
}

#[allow(clippy::too_many_arguments)]
async fn setup_with_sealer(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
    allowed_scopes: Option<Vec<String>>,
    endpoint_configuration: EndpointConfiguration,
    refresh_tokens: RefreshTokens,
    store: Arc<dyn TransientStore>,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    sealer: Arc<dyn Sealer>,
) -> (Router, tokio::task::JoinHandle<()>, MockCapture) {
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
        token_endpoint_auth_method,
    });
    let relay = Arc::new(Relay {
        key: key.clone(),
        upstream: key.clone(),
        client_auth: auth,
        scopes: vec!["openid".into(), "email".into()],
        allowed_scopes,
        required_id_token_claims: HashMap::new(),
        id_token_policy: None,
        refresh_tokens,
        redirect_policy: vec![
            RedirectMatcher::uri("https://app.example/callback").unwrap(),
            RedirectMatcher::uri("https://app.example/callback?channel=stable&next=%2Fhome")
                .unwrap(),
        ],
    });
    let mut resources = ProviderSnapshot::default();
    resources.upstreams.insert(key.clone(), upstream);
    resources.relays.insert(key, relay);
    let app = router(
        Arc::new(resources),
        RelayConfig {
            public_url: Url::parse("https://relay.example/").unwrap(),
            sealer,
            store: Some(store),
            http: reqwest::Client::new(),
            client_assertion_http: Default::default(),
            allow_localhost_loopback: false,
        },
        strategy,
    );
    (app, task, capture)
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
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
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
                id_token_policy: None,
                refresh_tokens: Default::default(),
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
            store: None,
            http: reqwest::Client::new(),
            client_assertion_http: Default::default(),
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
    authorization_code_with(app, path_key, challenge, "").await
}

async fn authorization_code_with(
    app: &Router,
    path_key: &str,
    challenge: Option<&str>,
    extra_query: &str,
) -> String {
    let mut uri = format!(
        "/relay/{path_key}/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=app-state"
    );
    if let Some(challenge) = challenge {
        uri.push_str("&code_challenge=");
        uri.push_str(challenge);
        uri.push_str("&code_challenge_method=S256");
    }
    uri.push_str(extra_query);
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

const SEALED: RefreshTokens = RefreshTokens {
    mode: RefreshTokenMode::Sealed,
    grace_period_seconds: DEFAULT_GRACE_PERIOD_SECONDS,
    max_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS,
};

async fn setup_sealed(
    auth: ClientAuth,
) -> (
    Router,
    Arc<XChaChaSealer>,
    tokio::task::JoinHandle<()>,
    MockCapture,
) {
    setup_with_refresh_tokens(
        "google",
        auth,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        SEALED,
    )
    .await
}

fn code_grant_form(code: &str, verifier: &str) -> String {
    serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap()
}

fn refresh_form(refresh_token: &str) -> String {
    serde_urlencoded::to_string([
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ])
    .unwrap()
}

const SEALED_VERIFIER: &str = "a-public-verifier-with-enough-entropy-123456789";

#[tokio::test]
async fn sealed_mode_replaces_the_refresh_token_on_the_code_grant() {
    let (app, sealer, task, _) = setup_sealed(ClientAuth::Public).await;
    let code = authorization_code(&app, "google", Some(&pkce_challenge(SEALED_VERIFIER))).await;
    let response = post_token(&app, "google", &code_grant_form(&code, SEALED_VERIFIER)).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.oauth-token+json"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains(r#""refresh""#), "{body}");
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["access_token"], "access");
    assert_eq!(value["token_type"], "Bearer");
    let handle = value["refresh_token"].as_str().unwrap();
    assert!(handle.starts_with("rrt1."));
    assert_eq!(
        open_handle(
            sealer.as_ref(),
            &ResourceKey::new("google").unwrap(),
            handle
        )
        .await
        .unwrap()
        .upstream_token,
        "refresh"
    );
    // Member order is the upstream's, not alphabetical.
    assert!(
        body.find("access_token").unwrap() < body.find("refresh_token").unwrap()
            && body.find("refresh_token").unwrap() < body.find("token_type").unwrap()
    );
    task.abort();
}

#[tokio::test]
async fn sealed_refresh_round_trips_through_the_upstream() {
    let (app, sealer, task, capture) = setup_sealed(ClientAuth::Public).await;
    let key = ResourceKey::new("google").unwrap();
    let handle = seal_handle(sealer.as_ref(), &key, "rotating", 1)
        .await
        .unwrap();

    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/json;charset=UTF-8"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.example"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains("rotated"), "{body}");
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["access_token"], "refreshed");
    assert_eq!(value["expires_in"], 3600);
    let new_handle = value["refresh_token"].as_str().unwrap();
    assert_eq!(
        open_handle(sealer.as_ref(), &key, new_handle)
            .await
            .unwrap()
            .upstream_token,
        "rotated"
    );
    assert!(
        body.find("token_type").unwrap() < body.find("refresh_token").unwrap()
            && body.find("refresh_token").unwrap() < body.find("access_token").unwrap()
    );

    let upstream_form = capture.token.lock().unwrap().last().unwrap().clone();
    assert!(upstream_form.contains(&("refresh_token".into(), "rotating".into())));
    assert!(upstream_form.contains(&("client_id".into(), "upstream-client".into())));
    assert!(upstream_form.contains(&("client_secret".into(), "upstream-secret".into())));
    assert!(!upstream_form.iter().any(|(_, value)| value == &handle));

    // The new handle keeps working.
    let again = post_token(&app, "google", &refresh_form(new_handle)).await;
    assert_eq!(again.status(), StatusCode::ACCEPTED);
    task.abort();
}

#[tokio::test]
async fn sealed_refresh_without_an_upstream_refresh_token_returns_none() {
    let (app, sealer, task, _) = setup_sealed(ClientAuth::Public).await;
    let handle = seal_handle(
        sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "refresh",
        1,
    )
    .await
    .unwrap();
    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response_body(response).await,
        br#"{"access_token":"refreshed","token_type":"Bearer"}"#
    );
    task.abort();
}

#[tokio::test]
async fn sealed_code_grant_without_an_upstream_refresh_token_is_unchanged() {
    let (app, _, task, _) = setup_sealed(ClientAuth::Public).await;
    let code = authorization_code_with(
        &app,
        "google",
        Some(&pkce_challenge(SEALED_VERIFIER)),
        "&login_hint=no-refresh",
    )
    .await;
    let response = post_token(&app, "google", &code_grant_form(&code, SEALED_VERIFIER)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        br#"{"access_token":"access","token_type":"Bearer"}"#
    );
    task.abort();
}

#[tokio::test]
async fn sealed_mode_rejects_raw_foreign_and_tampered_refresh_tokens() {
    let (app, sealer, task, capture) = setup_sealed(ClientAuth::Public).await;
    let key = ResourceKey::new("google").unwrap();
    let valid = seal_handle(sealer.as_ref(), &key, "refresh", 1)
        .await
        .unwrap();
    let foreign = seal_handle(
        sealer.as_ref(),
        &ResourceKey::new("other-relay").unwrap(),
        "refresh",
        1,
    )
    .await
    .unwrap();
    let other_install = seal_handle(
        &XChaChaSealer::new(&[99_u8; 32], None).unwrap(),
        &key,
        "refresh",
        1,
    )
    .await
    .unwrap();
    let mut tampered = valid.clone().into_bytes();
    *tampered.last_mut().unwrap() ^= 1;
    for presented in [
        "refresh".to_owned(),
        foreign,
        other_install,
        String::from_utf8(tampered).unwrap(),
        valid["rrt1.".len()..].to_owned(),
        String::new(),
    ] {
        let response = post_token(&app, "google", &refresh_form(&presented)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{presented}");
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(body["error"], "invalid_grant", "{presented}");
    }
    assert!(
        capture.token.lock().unwrap().is_empty(),
        "rejected refresh tokens must not reach the upstream"
    );
    let ok = post_token(&app, "google", &refresh_form(&valid)).await;
    assert_eq!(ok.status(), StatusCode::ACCEPTED);
    task.abort();
}

#[tokio::test]
async fn sealed_mode_applies_to_confidential_relays_and_checks_client_auth_first() {
    let auth = ClientAuth::ClientSecret {
        client_id: "application".into(),
        client_secret: SecretString::new("application-secret"),
    };
    let (app, sealer, task, _) = setup_sealed(auth).await;
    let handle = seal_handle(
        sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "rotating",
        1,
    )
    .await
    .unwrap();
    let form = |secret: &str| {
        format!(
            "{}&client_id=application&client_secret={secret}",
            refresh_form(&handle)
        )
    };
    assert_eq!(
        post_token(&app, "google", &form("wrong")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = post_token(&app, "google", &form("application-secret")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert!(value["refresh_token"]
        .as_str()
        .unwrap()
        .starts_with("rrt1."));
    task.abort();
}

#[tokio::test]
async fn passthrough_mode_returns_the_upstream_refresh_token_unchanged() {
    let (app, _, task, _) = setup_with_refresh_tokens(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        RefreshTokens::default(),
    )
    .await;
    assert_eq!(RefreshTokens::default().mode, RefreshTokenMode::Passthrough);
    let code = authorization_code(&app, "google", Some(&pkce_challenge(SEALED_VERIFIER))).await;
    let response = post_token(&app, "google", &code_grant_form(&code, SEALED_VERIFIER)).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response_body(response).await,
        br#"{"access_token":"access","refresh_token":"refresh","token_type":"Bearer"}"#
    );
    let response = post_token(&app, "google", &refresh_form("rotating")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        br#"{"token_type":"Bearer","refresh_token":"rotated","access_token":"refreshed","expires_in":3600}"#
    );
    task.abort();
}

/// Fails the first `put_if_absent`, then behaves like the wrapped store.
struct FlakyStore {
    inner: MemoryStore,
    failures: AtomicUsize,
}

#[async_trait::async_trait]
impl TransientStore for FlakyStore {
    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, crate::StoreError> {
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(crate::StoreError::Backend(anyhow::anyhow!("unavailable")));
        }
        self.inner.put_if_absent(key, value, ttl).await
    }

    async fn get(&self, key: &str) -> Result<Option<crate::Entry>, crate::StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: &[u8],
        new: &[u8],
        ttl: Duration,
    ) -> Result<bool, crate::StoreError> {
        self.inner.compare_and_swap(key, expected, new, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<(), crate::StoreError> {
        self.inner.delete(key).await
    }
}

/// Resolves a failed `put_if_absent` the way the DynamoDB store resolves an ambiguous conditional
/// write: a live record holding exactly the bytes being written counts as this caller's own write.
#[derive(Default)]
struct ValueResolvingStore(MemoryStore);

#[async_trait::async_trait]
impl TransientStore for ValueResolvingStore {
    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, crate::StoreError> {
        if self.0.put_if_absent(key, value, ttl).await? {
            return Ok(true);
        }
        Ok(self
            .0
            .get(key)
            .await?
            .is_some_and(|entry| entry.value == value))
    }

    async fn get(&self, key: &str) -> Result<Option<crate::Entry>, crate::StoreError> {
        self.0.get(key).await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: &[u8],
        new: &[u8],
        ttl: Duration,
    ) -> Result<bool, crate::StoreError> {
        self.0.compare_and_swap(key, expected, new, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<(), crate::StoreError> {
        self.0.delete(key).await
    }
}

#[tokio::test]
async fn code_replay_is_rejected_by_a_store_that_resolves_writes_by_value() {
    let (app, _, task, _) = setup_with_store(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        RefreshTokens::default(),
        Arc::new(ValueResolvingStore::default()),
    )
    .await;
    let verifier = "a-public-verifier-with-enough-entropy-123456789";
    let code = authorization_code(&app, "google", Some(&pkce_challenge(verifier))).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap();
    assert!(post_token(&app, "google", &form)
        .await
        .status()
        .is_success());
    let replay = post_token(&app, "google", &form).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&response_body(replay).await).unwrap();
    assert_eq!(body["error_description"], "code was already used");
    task.abort();
}

#[tokio::test]
async fn store_failure_is_retryable_and_leaves_the_code_unconsumed() {
    let (app, _, task, _) = setup_with_store(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        RefreshTokens::default(),
        Arc::new(FlakyStore {
            inner: MemoryStore::default(),
            failures: AtomicUsize::new(1),
        }),
    )
    .await;
    let verifier = "a-public-verifier-with-enough-entropy-123456789";
    let code = authorization_code(&app, "google", Some(&pkce_challenge(verifier))).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap();
    let unavailable = post_token(&app, "google", &form).await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(&response_body(unavailable).await).unwrap();
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        post_token(&app, "google", &form).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        post_token(&app, "google", &form).await.status(),
        StatusCode::BAD_REQUEST
    );
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
    assert!(capture
        .authorization
        .lock()
        .unwrap()
        .iter()
        .all(Option::is_none));
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
        .await
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
        .await
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
        .await
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
async fn id_token_policy_enforces_verified_domain_or_guest_at_code_redemption() {
    let policy: crate::IdTokenPolicy = serde_json::from_value(json!({
        "required": {"email_verified": {"booleanEquals": true}},
        "anyOf": [
            {"hd": {"stringEquals": "example.com"}},
            {"email": {"stringIn": ["guest@gmail.com"]}}
        ]
    }))
    .unwrap();
    let (app, fixture, task, redirect_uri, _) = setup_signed_policy(
        RelayProfile::Google,
        HashMap::from([("name".into(), "Fixture Person".into())]),
        Some(policy),
    )
    .await;
    for (overrides, accepted) in [
        (json!({}), true),
        (json!({"hd": null, "email": "guest@gmail.com"}), true),
        (json!({"hd": null, "email": "outsider@gmail.com"}), false),
        (
            json!({"hd": null, "email": "guest@gmail.com", "email_verified": false}),
            false,
        ),
        (
            json!({"hd": null, "email": "guest@gmail.com", "email_verified": "true"}),
            false,
        ),
        (
            json!({"hd": null, "email": "guest@gmail.com", "name": "Other Person"}),
            false,
        ),
        (json!({"iss": "https://untrusted.example"}), false),
        (json!({"aud": "other-client"}), false),
        (json!({"exp": 1}), false),
        (json!({"nonce": "wrong-nonce"}), false),
    ] {
        *fixture.claim_overrides.lock().unwrap() = overrides.as_object().unwrap().clone();
        let (code, verifier) = signed_authorization_code(&app, &redirect_uri).await;
        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .unwrap();
        let response = post_token(&app, "profile", &form).await;
        assert_eq!(
            response.status(),
            if accepted {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "{overrides}"
        );
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        if accepted {
            assert!(body.get("id_token").is_some());
        } else {
            assert_eq!(body["error"], "invalid_grant");
            assert!(body.get("id_token").is_none());
            assert!(body.get("access_token").is_none());
            assert!(body.get("refresh_token").is_none());
            let replay = post_token(&app, "profile", &form).await;
            let replay_body: Value = serde_json::from_slice(&response_body(replay).await).unwrap();
            assert_eq!(replay_body["error_description"], "code was already used");
        }
    }
    task.abort();
}

#[tokio::test]
async fn id_token_policy_requires_group_membership_from_array_claims() {
    let policy: crate::IdTokenPolicy = serde_json::from_value(json!({
        "required": {"groups": {"arrayContainsAny": ["admins", "ops"]}}
    }))
    .unwrap();
    let (app, fixture, task, redirect_uri, _) =
        setup_signed_policy(RelayProfile::Google, HashMap::new(), Some(policy)).await;
    for (overrides, accepted) in [
        (json!({"groups": ["eng", "ops"]}), true),
        (json!({"groups": ["admins"]}), true),
        (json!({"groups": ["eng"]}), false),
        (json!({"groups": []}), false),
        (json!({"groups": "ops"}), false),
        (json!({"groups": ["ops", 1]}), false),
        (json!({}), false),
    ] {
        *fixture.claim_overrides.lock().unwrap() = overrides.as_object().unwrap().clone();
        let (code, verifier) = signed_authorization_code(&app, &redirect_uri).await;
        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .unwrap();
        let response = post_token(&app, "profile", &form).await;
        assert_eq!(
            response.status(),
            if accepted {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "{overrides}"
        );
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        if accepted {
            assert!(body.get("id_token").is_some());
        } else {
            assert_eq!(body["error"], "invalid_grant");
            assert!(body.get("id_token").is_none());
            assert!(body.get("access_token").is_none());
            assert!(body.get("refresh_token").is_none());
            let replay = post_token(&app, "profile", &form).await;
            let replay_body: Value = serde_json::from_slice(&response_body(replay).await).unwrap();
            assert_eq!(replay_body["error_description"], "code was already used");
        }
    }
    task.abort();
}

#[tokio::test]
async fn string_like_policy_applies_only_to_initial_admission() {
    let policy: crate::IdTokenPolicy = serde_json::from_value(json!({
        "required": {"email": {"stringLike": "*@example.com"}}
    }))
    .unwrap();
    let (app, fixture, task, redirect_uri, _) =
        setup_signed_policy(RelayProfile::Google, HashMap::new(), Some(policy)).await;
    let (code, verifier) = signed_authorization_code(&app, &redirect_uri).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier.as_str()),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "profile", &form).await.status(),
        StatusCode::OK
    );
    fixture
        .claim_overrides
        .lock()
        .unwrap()
        .insert("email".into(), json!("person@example.com.evil"));
    let (code, verifier) = signed_authorization_code(&app, &redirect_uri).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier.as_str()),
    ])
    .unwrap();
    let denied = post_token(&app, "profile", &form).await;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    let denied_body: Value = serde_json::from_slice(&response_body(denied).await).unwrap();
    assert_eq!(denied_body["error"], "invalid_grant");
    assert!(denied_body.get("access_token").is_none());
    let refresh = post_token(
        &app,
        "profile",
        "grant_type=refresh_token&refresh_token=fixture-refresh-token",
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response_body(refresh).await).unwrap();
    assert_eq!(body["access_token"], "fixture-refreshed-access-token");
    assert!(body.get("id_token").is_none());
    task.abort();
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
    // Resolves writes by value like the DynamoDB store, so a constant replay marker would pass.
    let cache = Arc::new(ValueResolvingStore::default());
    let make_state = |store| AppState {
        resolver: Arc::new(ProviderSnapshot::default()),
        cfg: Arc::new(RelayConfig {
            public_url: "https://relay.example/".parse().unwrap(),
            sealer: Arc::new(XChaChaSealer::new(&[8; 32], None).unwrap()),
            store,
            http: reqwest::Client::new(),
            client_assertion_http: Default::default(),
            allow_localhost_loopback: false,
        }),
        keys: KeyStrategy::SingleSegment,
        cache: Arc::new(Mutex::new(HashMap::new())),
        assertion_cache: Arc::default(),
    };
    let state = make_state(Some(cache.clone() as Arc<dyn TransientStore>));
    let other_instance = make_state(Some(cache));
    let no_store = make_state(None);
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
        &no_store,
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
    // Workload assertions remain reusable without a transient store or per-request claims.
    let mut workload = claims.clone();
    workload.as_object_mut().unwrap().remove("jti");
    workload.as_object_mut().unwrap().remove("iat");
    workload["exp"] = json!(now + 3600);
    for _ in 0..2 {
        assert!(verify_private_key_jwt(
            &no_store,
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

fn assertion_test_state() -> AppState {
    AppState {
        resolver: Arc::new(ProviderSnapshot::default()),
        cfg: Arc::new(RelayConfig {
            public_url: "https://relay.example/".parse().unwrap(),
            sealer: Arc::new(XChaChaSealer::new(&[8; 32], None).unwrap()),
            store: None,
            http: reqwest::Client::new(),
            // Even a caller-supplied redirect policy cannot enable redirects for trust data.
            client_assertion_http: ClientAssertionHttpClient::new(
                reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(10)),
            )
            .unwrap(),
            allow_localhost_loopback: false,
        }),
        keys: KeyStrategy::SingleSegment,
        cache: Arc::default(),
        assertion_cache: Arc::default(),
    }
}

#[tokio::test]
async fn client_assertion_discovery_and_jwks_reject_redirects() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let jwks = json!({"keys":[{"kty":"RSA",
        "n":URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
        "e":URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())}]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/cluster", listener.local_addr().unwrap());
    let doc = json!({"issuer":issuer, "jwks_uri":format!("{issuer}/keys")});
    let target_hits = Arc::new(AtomicUsize::new(0));
    let hits = target_hits.clone();
    let discovery = doc.clone();
    let idp = Router::new()
        .route(
            "/cluster/.well-known/openid-configuration",
            get(move || {
                let discovery = discovery.clone();
                async move { Json(discovery) }
            }),
        )
        .route(
            "/redirect/.well-known/openid-configuration",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(
                        header::LOCATION,
                        "/cluster/.well-known/openid-configuration",
                    )],
                )
            }),
        )
        .route(
            "/cluster/keys",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/target-keys")]) }),
        )
        .route(
            "/target-keys",
            get(move || {
                let jwks = jwks.clone();
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(jwks)
                }
            }),
        );
    let task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let state = assertion_test_state();
    let claims = json!({"iss":issuer,"sub":"worker","aud":"relay","exp":unix_now()+3600});
    let assertion = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    for source in [
        None,
        Some(ClientJwks::Url(
            Url::parse(&format!("{issuer}/keys")).unwrap(),
        )),
    ] {
        assert!(verify_private_key_jwt(
            &state,
            "relay",
            &issuer,
            "worker",
            source.as_ref(),
            &assertion,
            false
        )
        .await
        .is_err());
    }
    let redirect_discovery =
        Url::parse(&issuer.replace("/cluster", "/redirect/.well-known/openid-configuration"))
            .unwrap();
    assert!(cached_json_with_client(
        &state.assertion_cache.metadata,
        &state.cfg.client_assertion_http.0,
        &redirect_discovery,
        DISCOVERY_TTL
    )
    .await
    .is_err());
    assert_eq!(
        target_hits.load(Ordering::SeqCst),
        0,
        "redirect target must never supply trusted keys"
    );
    assert!(!state
        .assertion_cache
        .metadata
        .lock()
        .await
        .contains_key(redirect_discovery.as_str()));
    let keys_url = Url::parse(&format!("{issuer}/keys")).unwrap();
    cached_json(&state, &keys_url, JWKS_TTL).await.unwrap();
    assert_eq!(target_hits.load(Ordering::SeqCst), 1);
    assert!(
        verify_private_key_jwt(&state, "relay", &issuer, "worker", None, &assertion, false)
            .await
            .is_err(),
        "upstream cache entries cannot supply assertion trust keys"
    );
    assert_eq!(target_hits.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn client_assertion_rotation_refreshes_once_and_throttles_unknown_keys() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let keys = Arc::new(StdMutex::new(json!({"keys":[{"kty":"RSA","kid":"old",
        "n":URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
        "e":URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())}]})));
    let hits = Arc::new(AtomicUsize::new(0));
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/cluster", listener.local_addr().unwrap());
    let keys_url = Url::parse(&format!("{issuer}/keys")).unwrap();
    let doc = json!({"issuer":issuer,"jwks_uri":keys_url});
    let served_keys = keys.clone();
    let requests = hits.clone();
    let fail = failing.clone();
    let idp = Router::new()
        .route(
            "/cluster/.well-known/openid-configuration",
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/cluster/keys",
            get(move || {
                let keys = served_keys.clone();
                let hits = requests.clone();
                let fail = fail.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    if fail.load(Ordering::SeqCst) {
                        StatusCode::SERVICE_UNAVAILABLE.into_response()
                    } else {
                        Json(keys.lock().unwrap().clone()).into_response()
                    }
                }
            }),
        );
    let task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let claims = json!({"iss":issuer,"sub":"worker","aud":"relay","exp":unix_now()+3600});
    let sign = |kid: &str| {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(&header, &claims, &key).unwrap()
    };
    // Both issuer-discovered keys and explicit remote JWKS use the refresh policy.
    for source in [None, Some(ClientJwks::Url(keys_url.clone()))] {
        keys.lock().unwrap()["keys"][0]["kid"] = json!("old");
        failing.store(false, Ordering::SeqCst);
        let state = assertion_test_state();
        let initial_hits = hits.load(Ordering::SeqCst);
        assert!(verify_private_key_jwt(
            &state,
            "relay",
            &issuer,
            "worker",
            source.as_ref(),
            &sign("old"),
            false
        )
        .await
        .is_ok());
        keys.lock().unwrap()["keys"][0]["kid"] = json!("new");
        let rotated = sign("new");
        let (a, b, c) = tokio::join!(
            verify_private_key_jwt(
                &state,
                "relay",
                &issuer,
                "worker",
                source.as_ref(),
                &rotated,
                false
            ),
            verify_private_key_jwt(
                &state,
                "relay",
                &issuer,
                "worker",
                source.as_ref(),
                &rotated,
                false
            ),
            verify_private_key_jwt(
                &state,
                "relay",
                &issuer,
                "worker",
                source.as_ref(),
                &rotated,
                false
            ),
        );
        assert!(a.is_ok() && b.is_ok() && c.is_ok());
        assert_eq!(
            hits.load(Ordering::SeqCst),
            initial_hits + 2,
            "rotation requires exactly one extra fetch"
        );
        for kid in ["unknown-1", "unknown-2", "unknown-3"] {
            assert!(verify_private_key_jwt(
                &state,
                "relay",
                &issuer,
                "worker",
                source.as_ref(),
                &sign(kid),
                false
            )
            .await
            .is_err());
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            initial_hits + 2,
            "unknown kids share a per-URL cooldown"
        );
        let entry = state.assertion_cache.jwks.lock().await[keys_url.as_str()].clone();
        entry.lock().await.retry_after = None;
        failing.store(true, Ordering::SeqCst);
        assert!(verify_private_key_jwt(
            &state,
            "relay",
            &issuer,
            "worker",
            source.as_ref(),
            &sign("missing"),
            false
        )
        .await
        .is_err());
        assert!(verify_private_key_jwt(
            &state,
            "relay",
            &issuer,
            "worker",
            source.as_ref(),
            &sign("missing-again"),
            false
        )
        .await
        .is_err());
        assert!(
            verify_private_key_jwt(
                &state,
                "relay",
                &issuer,
                "worker",
                source.as_ref(),
                &rotated,
                false
            )
            .await
            .is_ok(),
            "a failed refresh preserves fresh known keys"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            initial_hits + 3,
            "failed refreshes are throttled"
        );
        failing.store(false, Ordering::SeqCst);
        keys.lock().unwrap()["keys"][0]["kid"] = json!("recovered");
        entry.lock().await.retry_after = None;
        assert!(verify_private_key_jwt(
            &state,
            "relay",
            &issuer,
            "worker",
            source.as_ref(),
            &sign("recovered"),
            false
        )
        .await
        .is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), initial_hits + 4);
    }
    task.abort();
}

#[tokio::test]
async fn upstream_requests_ask_for_json() {
    let (app, sealer, task, capture) = setup_sealed(ClientAuth::Public).await;
    let code = authorization_code(&app, "google", Some(&pkce_challenge(SEALED_VERIFIER))).await;
    post_token(&app, "google", &code_grant_form(&code, SEALED_VERIFIER)).await;
    let handle = seal_handle(
        sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "refresh",
        1,
    )
    .await
    .unwrap();
    post_token(&app, "google", &refresh_form(&handle)).await;
    let accept = capture.accept.lock().unwrap().clone();
    assert_eq!(accept.len(), 2, "one code exchange and one refresh");
    assert!(accept
        .iter()
        .all(|value| value.as_deref() == Some("application/json")));
    task.abort();
}

/// `Authorization: Basic` for the upstream client `upstream-client` / `upstream-secret`.
const UPSTREAM_BASIC_AUTHORIZATION: &str = "Basic dXBzdHJlYW0tY2xpZW50OnVwc3RyZWFtLXNlY3JldA==";

/// Every token request the upstream saw carried the Basic credentials and none in its body.
fn assert_basic_upstream_requests(capture: &MockCapture, requests: usize) {
    let authorization = capture.authorization.lock().unwrap().clone();
    assert_eq!(authorization.len(), requests);
    assert!(authorization
        .iter()
        .all(|value| value.as_deref() == Some(UPSTREAM_BASIC_AUTHORIZATION)));
    let forms = capture.token.lock().unwrap().clone();
    assert_eq!(forms.len(), requests);
    for form in forms {
        assert!(
            !form
                .iter()
                .any(|(name, value)| name.starts_with("client_") || value.contains("-secret")),
            "{form:?}"
        );
    }
}

#[tokio::test]
async fn client_secret_basic_authenticates_the_code_exchange_and_passthrough_refresh() {
    let (app, _, task, capture) = setup_with_upstream_auth(
        "github",
        ClientAuth::UpstreamClient,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        RefreshTokens::default(),
        Arc::new(MemoryStore::default()),
        TokenEndpointAuthMethod::ClientSecretBasic,
    )
    .await;
    let code = authorization_code(&app, "github", None).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("client_id", "upstream-client"),
        ("client_secret", "upstream-secret"),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "github", &form).await.status(),
        StatusCode::CREATED
    );
    let refresh = "grant_type=refresh_token&refresh_token=refresh&client_id=upstream-client&client_secret=upstream-secret&scope=openid";
    assert_eq!(
        post_token(&app, "github", refresh).await.status(),
        StatusCode::ACCEPTED
    );
    assert_basic_upstream_requests(&capture, 2);
    let forms = capture.token.lock().unwrap().clone();
    assert!(forms[0].contains(&("grant_type".into(), "authorization_code".into())));
    assert!(forms[0].contains(&("code".into(), "upstream-code".into())));
    assert!(forms[1].contains(&("refresh_token".into(), "refresh".into())));
    assert!(forms[1].contains(&("scope".into(), "openid".into())));
    task.abort();
}

#[tokio::test]
async fn client_secret_basic_authenticates_sealed_refresh() {
    let (app, sealer, task, capture) = setup_with_upstream_auth(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        SEALED,
        Arc::new(MemoryStore::default()),
        TokenEndpointAuthMethod::ClientSecretBasic,
    )
    .await;
    let key = ResourceKey::new("google").unwrap();
    let handle = seal_handle(sealer.as_ref(), &key, "rotating", 1)
        .await
        .unwrap();
    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_basic_upstream_requests(&capture, 1);
    let forms = capture.token.lock().unwrap().clone();
    assert!(forms[0].contains(&("refresh_token".into(), "rotating".into())));
    task.abort();
}

#[tokio::test]
async fn client_secret_basic_authenticates_rotating_refresh() {
    let store = Arc::new(MemoryStore::default());
    let (app, sealer, task, capture) = setup_with_upstream_auth(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        rotating(ROTATING_GRACE_SECONDS),
        store.clone(),
        TokenEndpointAuthMethod::ClientSecretBasic,
    )
    .await;
    let handle = Rotator::new(
        store,
        sealer,
        ResourceKey::new("google").unwrap(),
        &rotating(ROTATING_GRACE_SECONDS),
    )
    .issue("rotating")
    .await
    .unwrap();
    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_basic_upstream_requests(&capture, 1);
    let forms = capture.token.lock().unwrap().clone();
    assert!(forms[0].contains(&("refresh_token".into(), "rotating".into())));
    task.abort();
}

#[test]
fn basic_authorization_form_urlencodes_both_credentials() {
    let value = basic_authorization("client:id", "se+cret %/é");
    let encoded = value.to_str().unwrap().strip_prefix("Basic ").unwrap();
    let decoded = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
    assert_eq!(decoded, "client%3Aid:se%2Bcret+%25%2F%C3%A9");
    assert!(value.is_sensitive());
}

/// `Authorization: Basic` as RFC 6749 section 2.3.1 builds it: form-urlencode each credential, join
/// with `:`, base64-encode.
fn basic_header(id: &str, secret: &str) -> String {
    let encode =
        |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", encode(id), encode(secret)))
    )
}

fn basic_header_for_raw(credentials: &[u8]) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

async fn post_token_with_authorization(
    app: &Router,
    path_key: &str,
    authorization: &[&[u8]],
    form: &str,
) -> Response {
    let mut request = Request::post(format!("/relay/{path_key}/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ORIGIN, "https://app.example");
    for value in authorization {
        request = request.header(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(value).unwrap(),
        );
    }
    app.clone()
        .oneshot(request.body(Body::from(form.to_owned())).unwrap())
        .await
        .unwrap()
}

async fn error_code(response: Response) -> String {
    let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    body["error"].as_str().unwrap().to_owned()
}

const APPLICATION_AUTH: fn() -> ClientAuth = || ClientAuth::ClientSecret {
    client_id: "application".into(),
    client_secret: SecretString::new("application-secret"),
};

fn code_form(code: &str) -> String {
    serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", "https://app.example/callback"),
    ])
    .unwrap()
}

#[tokio::test]
async fn basic_client_authentication_covers_code_exchange_and_refresh_for_client_secret_relays() {
    let (app, _, task, capture) = setup_with_upstream_auth(
        "github",
        APPLICATION_AUTH(),
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        RefreshTokens::default(),
        Arc::new(MemoryStore::default()),
        TokenEndpointAuthMethod::ClientSecretBasic,
    )
    .await;
    let basic = basic_header("application", "application-secret");
    let code = authorization_code(&app, "github", None).await;
    let response =
        post_token_with_authorization(&app, "github", &[basic.as_bytes()], &code_form(&code)).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = post_token_with_authorization(
        &app,
        "github",
        &[basic.as_bytes()],
        "grant_type=refresh_token&refresh_token=refresh&scope=openid",
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // The relying party's header is never forwarded: the upstream saw only its own credentials.
    assert_basic_upstream_requests(&capture, 2);
    task.abort();
}

#[tokio::test]
async fn basic_client_authentication_covers_code_exchange_and_refresh_for_upstream_client_relays() {
    let (app, _, task, capture) = setup_with_capture(
        "github",
        ClientAuth::UpstreamClient,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
    )
    .await;
    let basic = basic_header("upstream-client", "upstream-secret");
    let code = authorization_code(&app, "github", None).await;
    let response =
        post_token_with_authorization(&app, "github", &[basic.as_bytes()], &code_form(&code)).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = post_token_with_authorization(
        &app,
        "github",
        &[basic.as_bytes()],
        "grant_type=refresh_token&refresh_token=refresh",
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // The upstream is configured for form-body credentials: nothing from the header reaches it.
    assert!(capture
        .authorization
        .lock()
        .unwrap()
        .iter()
        .all(Option::is_none));
    let forms = capture.token.lock().unwrap().clone();
    assert_eq!(forms.len(), 2);
    for form in forms {
        assert!(form.contains(&("client_id".into(), "upstream-client".into())));
        assert!(form.contains(&("client_secret".into(), "upstream-secret".into())));
    }
    task.abort();
}

#[tokio::test]
async fn basic_client_authentication_rejects_wrong_credentials_with_a_challenge() {
    let (app, _, task) = setup("github", APPLICATION_AUTH(), KeyStrategy::SingleSegment).await;
    let refresh = "grant_type=refresh_token&refresh_token=refresh";
    for (id, secret) in [
        ("application", "wrong"),
        ("someone-else", "application-secret"),
        ("application", ""),
        ("", ""),
    ] {
        let basic = basic_header(id, secret);
        let response =
            post_token_with_authorization(&app, "github", &[basic.as_bytes()], refresh).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{id}:{secret}");
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"oauthrelay\""
        );
        assert_eq!(error_code(response).await, "invalid_client");
    }
    // Body credentials keep the response without a challenge.
    let response = post_token(
        &app,
        "github",
        &format!("{refresh}&client_id=application&client_secret=wrong"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(error_code(response).await, "invalid_client");
    task.abort();
}

#[tokio::test]
async fn upstream_client_relay_rejects_wrong_basic_credentials() {
    let (app, _, task) = setup(
        "github",
        ClientAuth::UpstreamClient,
        KeyStrategy::SingleSegment,
    )
    .await;
    let basic = basic_header("upstream-client", "wrong");
    let response = post_token_with_authorization(
        &app,
        "github",
        &[basic.as_bytes()],
        "grant_type=refresh_token&refresh_token=refresh",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    task.abort();
}

#[tokio::test]
async fn header_and_body_credentials_together_are_an_invalid_request() {
    for auth in [APPLICATION_AUTH(), ClientAuth::UpstreamClient] {
        let (id, secret) = match &auth {
            ClientAuth::UpstreamClient => ("upstream-client", "upstream-secret"),
            _ => ("application", "application-secret"),
        };
        let (app, _, task) = setup("github", auth, KeyStrategy::SingleSegment).await;
        let basic = basic_header(id, secret);
        let refresh = "grant_type=refresh_token&refresh_token=refresh";
        let conflicting = [
            format!("{refresh}&client_id={id}&client_secret={secret}"),
            format!("{refresh}&client_secret={secret}"),
            format!("{refresh}&client_id=another-client"),
            format!("{refresh}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=x"),
        ];
        for form in conflicting {
            let response =
                post_token_with_authorization(&app, "github", &[basic.as_bytes()], &form).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{form}");
            assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
            assert_eq!(error_code(response).await, "invalid_request");
        }
        // A body `client_id` that repeats the header's identifies the client; it is not a second
        // credential.
        let form = format!("{refresh}&client_id={id}");
        let response =
            post_token_with_authorization(&app, "github", &[basic.as_bytes()], &form).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        task.abort();
    }
}

#[tokio::test]
async fn malformed_authorization_headers_are_invalid_client_with_a_challenge() {
    let (app, _, task) = setup("github", APPLICATION_AUTH(), KeyStrategy::SingleSegment).await;
    let valid = basic_header("application", "application-secret");
    let malformed: Vec<Vec<Vec<u8>>> = vec![
        vec![b"Basic".to_vec()],
        vec![b"Basic ".to_vec()],
        vec![b"Basic !!!not-base64!!!".to_vec()],
        vec![b"Basic YXBwbGljYXRpb24".to_vec()],
        vec![basic_header_for_raw(b"application-without-colon").into_bytes()],
        vec![basic_header_for_raw(b"application:application%zzsecret").into_bytes()],
        vec![basic_header_for_raw(b"application:application%2").into_bytes()],
        vec![basic_header_for_raw(b"application%:secret").into_bytes()],
        vec![basic_header_for_raw(b"application:\xff\xfe").into_bytes()],
        vec![basic_header_for_raw(b"application:application%FF").into_bytes()],
        vec![b"Basic \xff".to_vec()],
        vec![valid.clone().into_bytes(), valid.clone().into_bytes()],
    ];
    for headers in malformed {
        let values: Vec<&[u8]> = headers.iter().map(Vec::as_slice).collect();
        let response = post_token_with_authorization(
            &app,
            "github",
            &values,
            "grant_type=refresh_token&refresh_token=refresh",
        )
        .await;
        let shown = format!("{headers:?}");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{shown}");
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"oauthrelay\"",
            "{shown}"
        );
        assert_eq!(error_code(response).await, "invalid_client", "{shown}");
    }
    task.abort();
}

#[tokio::test]
async fn non_basic_authorization_headers_leave_body_credentials_working() {
    for auth in [APPLICATION_AUTH(), ClientAuth::UpstreamClient] {
        let (id, secret) = match &auth {
            ClientAuth::UpstreamClient => ("upstream-client", "upstream-secret"),
            _ => ("application", "application-secret"),
        };
        let (app, _, task) = setup("github", auth, KeyStrategy::SingleSegment).await;
        let form = format!(
            "grant_type=refresh_token&refresh_token=refresh&client_id={id}&client_secret={secret}"
        );
        for value in [
            &b"Bearer gateway-token"[..],
            b"AWS4-HMAC-SHA256 Credential=x/y, Signature=z",
            b"Basicish abc",
        ] {
            let response = post_token_with_authorization(&app, "github", &[value], &form).await;
            assert_eq!(response.status(), StatusCode::ACCEPTED, "{value:?}");
        }
        // Without body credentials the request is simply unauthenticated, without a challenge.
        let response = post_token_with_authorization(
            &app,
            "github",
            &[b"Bearer gateway-token"],
            "grant_type=refresh_token&refresh_token=refresh",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
        task.abort();
    }
}

#[tokio::test]
async fn basic_authorization_accepts_any_scheme_case_and_both_space_encodings() {
    let auth = ClientAuth::ClientSecret {
        client_id: "application".into(),
        client_secret: SecretString::new("a b"),
    };
    let (app, _, task) = setup("github", auth, KeyStrategy::SingleSegment).await;
    let refresh = "grant_type=refresh_token&refresh_token=refresh";
    for credentials in [
        "application:a+b",
        "application:a%20b",
        "application:%61%20b",
    ] {
        for scheme in ["Basic", "basic", "BASIC"] {
            let value = format!("{scheme} {}", STANDARD.encode(credentials));
            let response =
                post_token_with_authorization(&app, "github", &[value.as_bytes()], refresh).await;
            assert_eq!(response.status(), StatusCode::ACCEPTED, "{value}");
        }
    }
    task.abort();
}

#[tokio::test]
async fn basic_credentials_round_trip_special_characters() {
    let id = "client/id with space";
    let secret = "a+b";
    let auth = ClientAuth::ClientSecret {
        client_id: id.into(),
        client_secret: SecretString::new(secret),
    };
    let (app, _, task) = setup("github", auth, KeyStrategy::SingleSegment).await;
    let refresh = "grant_type=refresh_token&refresh_token=refresh";
    let basic = basic_header(id, secret);
    let response =
        post_token_with_authorization(&app, "github", &[basic.as_bytes()], refresh).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // Unencoded, `+` decodes to a space, which is a different secret.
    let unencoded = basic_header_for_raw(format!("{id}:{secret}").as_bytes());
    let response =
        post_token_with_authorization(&app, "github", &[unencoded.as_bytes()], refresh).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let encoded = basic_header_for_raw(b"client%2Fid+with+space:a%2Bb");
    let response =
        post_token_with_authorization(&app, "github", &[encoded.as_bytes()], refresh).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    task.abort();
}

#[tokio::test]
async fn basic_credentials_round_trip_reserved_and_non_ascii_characters() {
    let id = "client:id/with space";
    let secret = "se+cret %/é:&=\u{1f512}";
    let auth = ClientAuth::ClientSecret {
        client_id: id.into(),
        client_secret: SecretString::new(secret),
    };
    let (app, _, task) = setup("github", auth, KeyStrategy::SingleSegment).await;
    let basic = basic_header(id, secret);
    let response = post_token_with_authorization(
        &app,
        "github",
        &[basic.as_bytes()],
        "grant_type=refresh_token&refresh_token=refresh",
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    task.abort();
}

#[tokio::test]
async fn public_relay_rejects_a_basic_authorization_header() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let refresh = "grant_type=refresh_token&refresh_token=refresh";
    for value in [
        basic_header("public-application", "secret"),
        "basic !!!".to_owned(),
        "Basic".to_owned(),
    ] {
        let response =
            post_token_with_authorization(&app, "google", &[value.as_bytes()], refresh).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{value}");
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"oauthrelay\""
        );
        assert_eq!(error_code(response).await, "invalid_client");
    }
    // Other schemes are not client credentials and are ignored, as the relay never reads them.
    let response = post_token_with_authorization(&app, "google", &[b"Bearer token"], refresh).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    task.abort();
}

#[tokio::test]
async fn public_relay_treats_a_basic_header_with_an_empty_secret_as_identification() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let refresh = "grant_type=refresh_token&refresh_token=refresh";
    let basic = basic_header("public-application", "");
    let response =
        post_token_with_authorization(&app, "google", &[basic.as_bytes()], refresh).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // A repeated body `client_id` is allowed; a different one conflicts.
    let same = format!("{refresh}&client_id=public-application");
    let response = post_token_with_authorization(&app, "google", &[basic.as_bytes()], &same).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let other = format!("{refresh}&client_id=another-client");
    let response = post_token_with_authorization(&app, "google", &[basic.as_bytes()], &other).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // A body secret alongside is still rejected, as without the header.
    let secret = format!("{refresh}&client_secret=x");
    let response =
        post_token_with_authorization(&app, "google", &[basic.as_bytes()], &secret).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Repeated Basic headers are unusable.
    let response = post_token_with_authorization(
        &app,
        "google",
        &[basic.as_bytes(), basic.as_bytes()],
        refresh,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    task.abort();
}

#[tokio::test]
async fn private_key_jwt_relay_does_not_read_the_authorization_header() {
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
        require_single_use: false,
        client_id: "jwt-application".into(),
        issuer: None,
        subject: None,
        audience: None,
        jwks: Some(ClientJwks::Inline(jwks)),
    };
    let (app, _, task) = setup("jwt", auth, KeyStrategy::SingleSegment).await;
    let basic = basic_header("jwt-application", "anything");
    // A Basic header is not a credential here.
    let response = post_token_with_authorization(
        &app,
        "jwt",
        &[basic.as_bytes()],
        "grant_type=refresh_token&refresh_token=refresh",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    // A valid assertion authenticates whatever the header says.
    let claims = json!({
        "iss": "jwt-application",
        "sub": "jwt-application",
        "aud": "https://relay.example/relay/jwt/token",
        "exp": unix_now() + 60,
        "iat": unix_now(),
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
        ("grant_type", "refresh_token"),
        ("refresh_token", "refresh"),
        ("client_id", "jwt-application"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = post_token_with_authorization(&app, "jwt", &[basic.as_bytes()], &form).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    task.abort();
}

#[test]
fn basic_credentials_parse_strictly() {
    let parse = |value: &str| parse_basic_credentials(value.as_bytes());
    assert_eq!(
        parse(&basic_header("a:b", "c d")),
        Some(("a:b".into(), "c d".into()))
    );
    assert_eq!(
        parse(&format!("Basic   {}", STANDARD.encode("a:b"))),
        Some(("a".into(), "b".into()))
    );
    // Only the first colon separates; an unencoded colon in the secret stays part of it.
    assert_eq!(
        parse(&basic_header_for_raw(b"a:b:c")),
        Some(("a".into(), "b:c".into()))
    );
    assert_eq!(parse("Basic"), None);
    assert_eq!(parse("Basicdmc6Yg=="), None);
    assert_eq!(form_urldecode(b"%e9"), None);
    assert_eq!(form_urldecode(b"%C3%A9+x").as_deref(), Some("é x"));
}

#[tokio::test]
async fn sealed_mode_substitutes_a_json_body_whatever_its_content_type() {
    let (app, sealer, task, _) = setup_sealed(ClientAuth::Public).await;
    let handle = seal_handle(
        sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "plain-json",
        1,
    )
    .await
    .unwrap();
    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains("plain-rotated"), "{body}");
    let value: Value = serde_json::from_str(&body).unwrap();
    assert!(value["refresh_token"]
        .as_str()
        .unwrap()
        .starts_with("rrt1."));
    task.abort();
}

#[tokio::test]
async fn sealed_mode_fails_closed_on_a_form_encoded_success_body() {
    let (app, sealer, task, _) = setup_sealed(ClientAuth::Public).await;
    let handle = seal_handle(
        sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "form-encoded",
        1,
    )
    .await
    .unwrap();
    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains("raw-secret"), "{body}");
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["error"], "server_error");

    let code = authorization_code_with(
        &app,
        "google",
        Some(&pkce_challenge(SEALED_VERIFIER)),
        "&login_hint=form-body",
    )
    .await;
    let response = post_token(&app, "google", &code_grant_form(&code, SEALED_VERIFIER)).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains("raw-secret"), "{body}");
    task.abort();
}

#[tokio::test]
async fn passthrough_mode_returns_a_form_encoded_body_unchanged() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let response = post_token(&app, "google", &refresh_form("form-encoded")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        b"access_token=form&refresh_token=raw-secret&token_type=Bearer"
    );
    task.abort();
}

#[tokio::test]
async fn handle_prefixed_tokens_are_never_forwarded_in_any_mode() {
    let (passthrough, _, task1, capture1) = setup_with_capture(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
    )
    .await;
    let (sealed, _, task2, capture2) = setup_sealed(ClientAuth::Public).await;
    for (app, capture) in [(&passthrough, &capture1), (&sealed, &capture2)] {
        for presented in ["rrt1.anything", "rrt2.anything", "rrt7.anything"] {
            let response = post_token(app, "google", &refresh_form(presented)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{presented}");
            let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
            assert_eq!(body["error"], "invalid_grant", "{presented}");
        }
        assert!(
            capture.token.lock().unwrap().is_empty(),
            "a handle must not reach the upstream"
        );
    }
    // A raw token that merely resembles the prefix is an ordinary upstream token.
    let response = post_token(&passthrough, "google", &refresh_form("rrt-not-a-handle")).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    task1.abort();
    task2.abort();
}

#[tokio::test]
async fn sealed_refresh_passes_upstream_errors_through_and_reports_transport_failures() {
    let (app, sealer, task, _) = setup_with_refresh_tokens(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Explicit,
        SEALED,
    )
    .await;
    let key = ResourceKey::new("google").unwrap();
    let handle = async |token: &str| seal_handle(sealer.as_ref(), &key, token, 1).await.unwrap();

    let response = post_token(
        &app,
        "google",
        &refresh_form(&handle("broken-upstream").await),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_body(response).await,
        br#"{"error":"server_error"}"#
    );
    let response = post_token(
        &app,
        "google",
        &refresh_form(&handle("revoked-upstream").await),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await,
        br#"{"error":"invalid_grant","error_description":"Token has been revoked"}"#
    );

    // With the upstream gone the failure is a 502 server_error, not a hang or a raw error.
    task.abort();
    let _ = task.await;
    let response = post_token(&app, "google", &refresh_form(&handle("rotating").await)).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert_eq!(body["error"], "server_error");
}

const ROTATING_GRACE_SECONDS: u64 = 1;

fn rotating(grace_period_seconds: u64) -> RefreshTokens {
    RefreshTokens {
        mode: RefreshTokenMode::Rotating,
        grace_period_seconds,
        max_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS,
    }
}

struct RotatingFixture {
    app: Router,
    sealer: Arc<XChaChaSealer>,
    store: Arc<MemoryStore>,
    capture: MockCapture,
    task: tokio::task::JoinHandle<()>,
}

impl RotatingFixture {
    async fn new(grace_period_seconds: u64) -> Self {
        let store = Arc::new(MemoryStore::default());
        let (app, sealer, task, capture) = setup_with_store(
            "google",
            ClientAuth::Public,
            KeyStrategy::SingleSegment,
            None,
            EndpointConfiguration::Discovered,
            rotating(grace_period_seconds),
            store.clone(),
        )
        .await;
        Self {
            app,
            sealer,
            store,
            capture,
            task,
        }
    }

    /// A handle whose upstream refresh token is `upstream_token`, as the code grant would issue.
    async fn handle_for(&self, upstream_token: &str) -> String {
        Rotator::new(
            self.store.clone(),
            self.sealer.clone(),
            ResourceKey::new("google").unwrap(),
            &rotating(ROTATING_GRACE_SECONDS),
        )
        .issue(upstream_token)
        .await
        .unwrap()
    }

    async fn refresh(&self, handle: &str) -> (StatusCode, Value) {
        let response = post_token(&self.app, "google", &refresh_form(handle)).await;
        let status = response.status();
        (
            status,
            serde_json::from_slice(&response_body(response).await).unwrap(),
        )
    }

    fn upstream_refreshes(&self) -> Vec<String> {
        self.capture
            .token
            .lock()
            .unwrap()
            .iter()
            .filter(|form| form.contains(&("grant_type".into(), "refresh_token".into())))
            .filter_map(|form| {
                form.iter()
                    .find(|(name, _)| name == "refresh_token")
                    .map(|(_, value)| value.clone())
            })
            .collect()
    }
}

#[tokio::test]
async fn rotating_code_grant_issues_a_stateful_handle() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let code = authorization_code(
        &fixture.app,
        "google",
        Some(&pkce_challenge(SEALED_VERIFIER)),
    )
    .await;
    let response = post_token(
        &fixture.app,
        "google",
        &code_grant_form(&code, SEALED_VERIFIER),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.oauth-token+json"
    );
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains(r#""refresh""#), "{body}");
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["access_token"], "access");
    let handle = value["refresh_token"].as_str().unwrap();
    assert!(handle.starts_with("rrt2."), "{handle}");
    assert!(
        body.find("access_token").unwrap() < body.find("refresh_token").unwrap()
            && body.find("refresh_token").unwrap() < body.find("token_type").unwrap()
    );
    // The handle is the only way back to the upstream token.
    let (status, refreshed) = fixture.refresh(handle).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(refreshed["access_token"], "refreshed");
    assert_eq!(fixture.upstream_refreshes(), ["refresh"]);
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_code_grant_without_an_upstream_refresh_token_is_unchanged() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let code = authorization_code_with(
        &fixture.app,
        "google",
        Some(&pkce_challenge(SEALED_VERIFIER)),
        "&login_hint=no-refresh",
    )
    .await;
    let response = post_token(
        &fixture.app,
        "google",
        &code_grant_form(&code, SEALED_VERIFIER),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        br#"{"access_token":"access","token_type":"Bearer"}"#
    );
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_refresh_rotates_replays_within_grace_and_revokes_on_reuse() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let first = fixture.handle_for("rotating").await;

    let (status, rotated) = fixture.refresh(&first).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rotated["access_token"], "refreshed");
    let second = rotated["refresh_token"].as_str().unwrap().to_owned();
    assert!(second.starts_with("rrt2.") && second != first);
    assert!(!rotated.to_string().contains("rotated"));

    // A duplicate within the grace period is answered with the recorded response and does not
    // reach the upstream.
    let (status, replay) = fixture.refresh(&first).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, rotated);
    assert_eq!(fixture.upstream_refreshes(), ["rotating"]);

    // The successor wraps the token the upstream rotated to.
    let (status, next) = fixture.refresh(&second).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(fixture.upstream_refreshes(), ["rotating", "rotated"]);
    let third = next["refresh_token"].as_str().unwrap().to_owned();
    assert!(third.starts_with("rrt2."));

    // After the grace period the first handle is a replay: invalid_grant, and the whole family
    // is revoked, including handles that were valid a moment ago.
    tokio::time::sleep(Duration::from_millis(ROTATING_GRACE_SECONDS * 1000 + 250)).await;
    let (status, reuse) = fixture.refresh(&first).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reuse["error"], "invalid_grant");
    for handle in [&second, &third] {
        let (status, failed) = fixture.refresh(handle).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(failed["error"], "invalid_grant");
    }
    assert_eq!(fixture.upstream_refreshes().len(), 2);
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_refresh_without_upstream_rotation_keeps_the_upstream_token() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let first = fixture.handle_for("refresh").await;
    let (_, rotated) = fixture.refresh(&first).await;
    let second = rotated["refresh_token"].as_str().unwrap();
    assert!(second.starts_with("rrt2."));
    assert_eq!(rotated["token_type"], "Bearer");
    fixture.refresh(second).await;
    assert_eq!(fixture.upstream_refreshes(), ["refresh", "refresh"]);
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_upstream_errors_keep_the_handle_but_invalid_grant_revokes_it() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let broken = fixture.handle_for("broken-upstream").await;
    for _ in 0..2 {
        let (status, body) = fixture.refresh(&broken).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "server_error");
    }
    assert_eq!(
        fixture.upstream_refreshes().len(),
        2,
        "the claim was released"
    );

    let revoked = fixture.handle_for("revoked-upstream").await;
    let (status, body) = fixture.refresh(&revoked).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Token has been revoked");
    let (status, body) = fixture.refresh(&revoked).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "invalid refresh token");
    assert_eq!(
        fixture.upstream_refreshes().len(),
        3,
        "a revoked family is not retried upstream"
    );
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_mode_migrates_sealed_handles_and_rejects_raw_tokens() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let sealed = seal_handle(
        fixture.sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "rotating",
        unix_now(),
    )
    .await
    .unwrap();
    let (status, body) = fixture.refresh(&sealed).await;
    assert_eq!(status, StatusCode::OK);
    let handle = body["refresh_token"].as_str().unwrap();
    assert!(handle.starts_with("rrt2."));
    let (status, _) = fixture.refresh(handle).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(fixture.upstream_refreshes(), ["rotating", "rotated"]);

    // A sealed handle older than the family lifetime is not migrated.
    let expired = seal_handle(
        fixture.sealer.as_ref(),
        &ResourceKey::new("google").unwrap(),
        "rotating",
        unix_now() - DEFAULT_MAX_LIFETIME_SECONDS,
    )
    .await
    .unwrap();
    let (status, body) = fixture.refresh(&expired).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(fixture.upstream_refreshes().len(), 2);

    for presented in ["rotating", "", "rrt2.", "rrt2.unknown"] {
        let (status, body) = fixture.refresh(presented).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{presented}");
        assert_eq!(body["error"], "invalid_grant", "{presented}");
    }
    assert_eq!(fixture.upstream_refreshes().len(), 2);
    fixture.task.abort();
}

#[tokio::test]
async fn sealed_mode_rejects_rotating_handles() {
    let (app, _, task, capture) = setup_sealed(ClientAuth::Public).await;
    let handle = format!("rrt2.{}", URL_SAFE_NO_PAD.encode([5_u8; 32]));
    let response = post_token(&app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(capture.token.lock().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn rotating_relay_without_a_store_fails_with_a_server_error() {
    let key = ResourceKey::new("google").unwrap();
    let mut resources = ProviderSnapshot::default();
    resources.upstreams.insert(
        key.clone(),
        Arc::new(Upstream {
            key: key.clone(),
            issuer_url: Url::parse("https://issuer.example").unwrap(),
            authorization_endpoint: Some(Url::parse("https://issuer.example/authorize").unwrap()),
            token_endpoint: Some(Url::parse("https://issuer.example/token").unwrap()),
            jwks_uri: None,
            client_id: "upstream-client".into(),
            client_secret: SecretString::new("upstream-secret"),
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        }),
    );
    resources.relays.insert(
        key.clone(),
        Arc::new(Relay {
            key: key.clone(),
            upstream: key,
            client_auth: ClientAuth::Public,
            scopes: vec!["openid".into()],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            id_token_policy: None,
            refresh_tokens: rotating(30),
            redirect_policy: vec![RedirectMatcher::uri("https://app.example/callback").unwrap()],
        }),
    );
    let app = router(
        Arc::new(resources),
        RelayConfig {
            public_url: Url::parse("https://relay.example/").unwrap(),
            sealer: Arc::new(XChaChaSealer::new(&[7_u8; 32], None).unwrap()),
            store: None,
            http: reqwest::Client::new(),
            client_assertion_http: Default::default(),
            allow_localhost_loopback: false,
        },
        KeyStrategy::SingleSegment,
    );
    let authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={}&code_challenge_method=S256",
                pkce_challenge(SEALED_VERIFIER)
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::INTERNAL_SERVER_ERROR);
    for form in [
        refresh_form("rrt2.anything"),
        code_grant_form("any-code", SEALED_VERIFIER),
    ] {
        let logs = LogCapture::default();
        let response = {
            let _guard = tracing::subscriber::set_default(logs.subscriber());
            post_token(&app, "google", &form).await
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(body["error"], "server_error");
        let output = logs.output();
        assert!(
            output.contains("no transient store") && output.contains("google"),
            "every grant logs the missing store and names the relay: {output}"
        );
    }
}

/// Collects formatted log output for one test, on the current thread only.
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish()
    }

    fn output(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[tokio::test]
async fn rotating_mode_fails_closed_on_a_form_encoded_success_body() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let handle = fixture.handle_for("form-encoded").await;
    for _ in 0..2 {
        let response = post_token(&fixture.app, "google", &refresh_form(&handle)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = String::from_utf8(response_body(response).await).unwrap();
        assert!(!body.contains("raw-secret"), "{body}");
        assert!(body.contains("server_error"));
    }
    assert_eq!(
        fixture.upstream_refreshes().len(),
        2,
        "the claim is released after an unusable response"
    );

    let code = authorization_code_with(
        &fixture.app,
        "google",
        Some(&pkce_challenge(SEALED_VERIFIER)),
        "&login_hint=form-body",
    )
    .await;
    let response = post_token(
        &fixture.app,
        "google",
        &code_grant_form(&code, SEALED_VERIFIER),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains("raw-secret"), "{body}");
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_mode_treats_json_as_json_whatever_the_content_type() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    let handle = fixture.handle_for("plain-json").await;
    let response = post_token(&fixture.app, "google", &refresh_form(&handle)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains("plain-rotated"), "{body}");
    let value: Value = serde_json::from_str(&body).unwrap();
    assert!(value["refresh_token"]
        .as_str()
        .unwrap()
        .starts_with("rrt2."));
    fixture.task.abort();
}

#[tokio::test]
async fn rotating_mode_never_forwards_handle_prefixed_tokens_unopened() {
    let fixture = RotatingFixture::new(ROTATING_GRACE_SECONDS).await;
    for presented in ["rrt1.anything", "rrt2.anything", "rrt9.anything"] {
        let (status, body) = fixture.refresh(presented).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{presented}");
        assert_eq!(body["error"], "invalid_grant", "{presented}");
    }
    assert!(fixture.upstream_refreshes().is_empty());
    fixture.task.abort();
}

/// A relay whose sealer can be switched off, as a remote key service going down would.
async fn setup_flaky(
    refresh_tokens: RefreshTokens,
) -> (
    Router,
    Arc<FlakySealer>,
    Arc<MemoryStore>,
    tokio::task::JoinHandle<()>,
    MockCapture,
) {
    let sealer = Arc::new(FlakySealer::new(&[7_u8; 32]));
    let store = Arc::new(MemoryStore::default());
    let (app, task, capture) = setup_with_sealer(
        "google",
        ClientAuth::Public,
        KeyStrategy::SingleSegment,
        None,
        EndpointConfiguration::Discovered,
        refresh_tokens,
        store.clone(),
        TokenEndpointAuthMethod::ClientSecretPost,
        sealer.clone(),
    )
    .await;
    (app, sealer, store, task, capture)
}

async fn assert_sealer_unavailable(response: Response) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_body(response).await;
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"], "server_error", "{value}");
    // Nothing from the upstream's token response leaks.
    let text = String::from_utf8(body).unwrap();
    assert!(
        !text.contains("access") && !text.contains("refresh"),
        "{text}"
    );
}

#[tokio::test]
async fn an_unavailable_sealer_fails_the_authorize_and_callback_legs_with_503() {
    let (app, sealer, _, task, _) = setup_flaky(Default::default()).await;
    let challenge = pkce_challenge(SEALED_VERIFIER);
    let authorize = || {
        app.clone().oneshot(
            Request::get(format!(
                "/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap(),
        )
    };
    sealer.set_seal_down(true);
    assert_eq!(
        authorize().await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    // The callback cannot open its state while the sealer is down; a forged state is still 400.
    sealer.set_seal_down(false);
    let upstream_location = authorize().await.unwrap().headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let state = Url::parse(&upstream_location)
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = |state: &str| {
        app.clone().oneshot(
            Request::get(format!(
                "/upstream/google/callback?code=upstream-code&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
    };
    sealer.set_unseal_down(true);
    assert_eq!(
        callback(&state).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sealer.set_unseal_down(false);
    assert_eq!(
        callback("forged").await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    task.abort();
}

#[tokio::test]
async fn an_unavailable_sealer_leaves_a_sealed_mode_code_redeemable() {
    let (app, sealer, _, task, _) = setup_flaky(SEALED).await;
    let code = authorization_code(&app, "google", Some(&pkce_challenge(SEALED_VERIFIER))).await;
    let form = code_grant_form(&code, SEALED_VERIFIER);

    // The code cannot be opened.
    sealer.set_unseal_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    sealer.set_unseal_down(false);

    // The code opens but the refresh handle cannot be sealed: the upstream token is not
    // returned, and the code was not consumed.
    sealer.set_seal_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    sealer.set_seal_down(false);

    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = String::from_utf8(response_body(response).await).unwrap();
    assert!(!body.contains(r#""refresh""#), "{body}");
    assert!(body.contains("rrt1."), "{body}");

    // Now it is used.
    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn an_unavailable_sealer_consumes_a_rotating_mode_code_once_the_family_is_written() {
    let (app, sealer, _, task, _) = setup_flaky(rotating(ROTATING_GRACE_SECONDS)).await;
    let code = authorization_code(&app, "google", Some(&pkce_challenge(SEALED_VERIFIER))).await;
    let form = code_grant_form(&code, SEALED_VERIFIER);

    // The code cannot be opened, so it is not consumed.
    sealer.set_unseal_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    sealer.set_unseal_down(false);

    // The family cannot be sealed. The replay marker is written first, because issuing the
    // family writes to the store, so the code is spent and the client signs in again.
    sealer.set_seal_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    sealer.set_seal_down(false);

    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert_eq!(value["error"], "invalid_grant");
    assert_eq!(value["error_description"], "code was already used");
    task.abort();
}

#[tokio::test]
async fn a_seal_failure_at_the_callback_returns_a_bare_503_and_no_code() {
    let (app, sealer, _, task, _) = setup_flaky(Default::default()).await;
    let challenge = pkce_challenge(SEALED_VERIFIER);
    let authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/relay/google/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=app-state&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::FOUND);
    let upstream_location = authorize.headers()[header::LOCATION].to_str().unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let upstream = client.get(upstream_location).send().await.unwrap();
    let callback = Url::parse(upstream.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let local_callback = format!("{}?{}", callback.path(), callback.query().unwrap());

    // The state opens and the upstream code exchange succeeds; sealing the code envelope fails.
    sealer.set_seal_down(true);
    let response = app
        .clone()
        .oneshot(Request::get(&local_callback).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::LOCATION).is_none());
    assert!(response_body(response).await.is_empty());
    task.abort();
}

#[tokio::test]
async fn an_unavailable_sealer_fails_a_sealed_refresh_with_503_and_keeps_the_handle_valid() {
    let (app, sealer, _, task, capture) = setup_flaky(SEALED).await;
    let key = ResourceKey::new("google").unwrap();
    let handle = seal_handle(sealer.as_ref(), &key, "rotating", 1)
        .await
        .unwrap();
    let form = refresh_form(&handle);

    // The handle cannot be opened: not invalid_grant, and the upstream is not contacted.
    sealer.set_unseal_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    assert!(capture.token.lock().unwrap().is_empty());
    sealer.set_unseal_down(false);

    // The handle opens but the upstream's new refresh token cannot be sealed: it is not returned.
    sealer.set_seal_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    sealer.set_seal_down(false);

    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::OK);

    // A bad handle is still an invalid_grant while the sealer is up.
    let response = post_token(&app, "google", &refresh_form("rrt1.garbage")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn an_unavailable_sealer_fails_a_rotating_refresh_with_503_and_keeps_the_family() {
    let (app, sealer, store, task, capture) = setup_flaky(rotating(ROTATING_GRACE_SECONDS)).await;
    let handle = Rotator::new(
        store.clone(),
        sealer.clone(),
        ResourceKey::new("google").unwrap(),
        &rotating(ROTATING_GRACE_SECONDS),
    )
    .issue("rotating-upstream")
    .await
    .unwrap();
    let form = refresh_form(&handle);

    sealer.set_down(true);
    assert_sealer_unavailable(post_token(&app, "google", &form).await).await;
    assert!(capture.token.lock().unwrap().is_empty());
    sealer.set_down(false);

    // The family is neither revoked nor discarded: the same handle refreshes once the sealer
    // is back.
    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::OK);
    task.abort();
}
