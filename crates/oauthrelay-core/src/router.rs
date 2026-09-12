use crate::{
    model::valid_scope_token, ClientAuth, ClientJwks, Relay, ReplayCache, ResourceKey,
    ResourceResolver, Sealer, Upstream,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{collections::HashMap, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use url::Url;

const FLOW_TTL: u64 = 10 * 60;
const CODE_TTL: u64 = 5 * 60;
const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60);
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);
const ID_TOKEN_CLOCK_SKEW: u64 = 60;

pub struct RelayConfig {
    pub public_url: Url,
    pub sealer: Arc<dyn Sealer>,
    pub replay_cache: Option<Arc<dyn ReplayCache>>,
    pub http: reqwest::Client,
    pub allow_localhost_loopback: bool,
}

#[derive(Clone)]
pub enum KeyStrategy {
    SingleSegment,
    TwoSegment,
    Custom(Arc<KeyMapper>),
}

pub type KeyMapper = dyn Fn(&[&str]) -> Option<ResourceKey> + Send + Sync;

#[derive(Clone)]
struct AppState {
    resolver: Arc<dyn ResourceResolver>,
    cfg: Arc<RelayConfig>,
    keys: KeyStrategy,
    cache: Arc<Mutex<HashMap<String, CachedJson>>>,
}

#[derive(Clone)]
struct CachedJson {
    fetched: std::time::Instant,
    value: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct FlowEnvelope {
    relay_key: String,
    app_redirect_uri: String,
    app_state: Option<String>,
    upstream_pkce_verifier: String,
    client_code_challenge: Option<String>,
    client_code_challenge_method: Option<String>,
    id_token_nonce: Option<String>,
    issued_at: u64,
    nonce: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize)]
struct CodeEnvelope {
    relay_key: String,
    envelope_id: [u8; 16],
    issued_at: u64,
    redirect_uri: String,
    client_code_challenge: Option<String>,
    id_token_nonce: Option<String>,
    upstream_response: StoredResponse,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct AuthorizeRequest {
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    id_token_nonce: Option<String>,
    scope: Option<String>,
    forwarded: Vec<(String, String)>,
}

struct CallbackRequest {
    code: Option<String>,
    state: String,
    error: bool,
    forwarded: Vec<(String, String)>,
}

struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    scope: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    pairs: Vec<(String, String)>,
}

#[derive(Clone, Copy)]
enum Endpoint {
    Authorize,
    Callback,
    Token,
    Discovery,
    Jwks,
}

pub fn router(resolver: Arc<dyn ResourceResolver>, cfg: RelayConfig, keys: KeyStrategy) -> Router {
    let route = public_route_pattern(&cfg.public_url);
    let state = AppState {
        resolver,
        cfg: Arc::new(cfg),
        keys,
        cache: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new().route(&route, any(dispatch)).with_state(state)
}

async fn dispatch(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    let Some((key, endpoint)) = parse_path(&path, &state.keys) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if matches!(endpoint, Endpoint::Callback) {
        let upstream = match state.resolver.resolve_upstream(&key).await {
            Ok(Some(upstream)) => upstream,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if upstream.validate().is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        if request.method() != Method::GET {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let query = match parse_callback_request(request.uri()) {
            Ok(query) => query,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        return callback(&state, &upstream, query).await;
    }

    let relay = match state.resolver.resolve_relay(&key).await {
        Ok(Some(relay)) => relay,
        Ok(None) if matches!(endpoint, Endpoint::Token) => {
            return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "unknown relay")
        }
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) if matches!(endpoint, Endpoint::Token) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "relay resolution failed",
            )
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let upstream = match state.resolver.resolve_upstream(&relay.upstream).await {
        Ok(Some(upstream)) => upstream,
        Ok(None) if matches!(endpoint, Endpoint::Token) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "relay upstream is unavailable",
            )
        }
        Ok(None) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Err(_) if matches!(endpoint, Endpoint::Token) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "upstream resolution failed",
            )
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if let Err(error) = relay.validate() {
        tracing::error!(%key, %error, "resolved relay is invalid");
        if matches!(endpoint, Endpoint::Token) {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "relay configuration is invalid",
            );
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let method = request.method().clone();
    match (endpoint, method) {
        (Endpoint::Authorize, Method::GET) => {
            let query = match parse_authorize_request(request.uri()) {
                Ok(query) => query,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            };
            authorize(&state, &relay, &upstream, query).await
        }
        (Endpoint::Token, Method::OPTIONS) => preflight(
            &relay,
            request.headers(),
            state.cfg.allow_localhost_loopback,
        ),
        (Endpoint::Token, Method::POST) => token(&state, &relay, &upstream, request).await,
        (Endpoint::Discovery, Method::GET) => discovery(&state, &relay, &upstream).await,
        (Endpoint::Jwks, Method::GET) => jwks(&state, &upstream).await,
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn parse_path(path: &str, strategy: &KeyStrategy) -> Option<(ResourceKey, Endpoint)> {
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    let (namespace, namespaced) = segments.split_first()?;
    let (key_parts, endpoint) = match *namespace {
        "upstream" if namespaced.last() == Some(&"callback") => (
            &namespaced[..namespaced.len().checked_sub(1)?],
            Endpoint::Callback,
        ),
        "relay" if namespaced.ends_with(&[".well-known", "openid-configuration"]) => (
            &namespaced[..namespaced.len().checked_sub(2)?],
            Endpoint::Discovery,
        ),
        "relay" => {
            let endpoint = match *namespaced.last()? {
                "authorize" => Endpoint::Authorize,
                "token" => Endpoint::Token,
                "jwks" => Endpoint::Jwks,
                _ => return None,
            };
            (&namespaced[..namespaced.len().checked_sub(1)?], endpoint)
        }
        _ => return None,
    };
    let key = match strategy {
        KeyStrategy::SingleSegment if key_parts.len() == 1 => ResourceKey::new(key_parts[0]).ok(),
        KeyStrategy::TwoSegment if key_parts.len() == 2 => {
            ResourceKey::new(format!("{}/{}", key_parts[0], key_parts[1])).ok()
        }
        KeyStrategy::Custom(map) => map(key_parts),
        _ => None,
    }?;
    Some((key, endpoint))
}

fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
    url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

fn parse_authorize_request(uri: &Uri) -> Result<AuthorizeRequest, ()> {
    let mut redirect_uri = None;
    let mut state = None;
    let mut code_challenge = None;
    let mut code_challenge_method = None;
    let mut id_token_nonce = None;
    let mut scope = None;
    let mut forwarded = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (name, value) in query_pairs(uri) {
        let singleton = matches!(
            name.as_str(),
            "redirect_uri"
                | "state"
                | "client_id"
                | "response_type"
                | "response_mode"
                | "code_challenge"
                | "code_challenge_method"
                | "scope"
                | "nonce"
                | "prompt"
                | "login_hint"
                | "request"
                | "request_uri"
        );
        if singleton && !seen.insert(name.clone()) {
            return Err(());
        }
        match name.as_str() {
            "redirect_uri" => redirect_uri = Some(value),
            "state" => state = Some(value),
            "client_id" => {}
            "response_type" if value == "code" => {}
            "response_type" => return Err(()),
            "response_mode" if value == "query" => forwarded.push((name, value)),
            "response_mode" => return Err(()),
            "code_challenge" => code_challenge = Some(value),
            "code_challenge_method" => code_challenge_method = Some(value),
            "scope" => scope = Some(value),
            "nonce" => {
                id_token_nonce = Some(value.clone());
                forwarded.push((name, value));
            }
            "request" | "request_uri" => return Err(()),
            _ => forwarded.push((name, value)),
        }
    }

    Ok(AuthorizeRequest {
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        id_token_nonce,
        scope,
        forwarded,
    })
}

fn parse_callback_request(uri: &Uri) -> Result<CallbackRequest, ()> {
    let mut code = None;
    let mut state = None;
    let mut error = false;
    let mut forwarded = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (name, value) in query_pairs(uri) {
        if matches!(name.as_str(), "code" | "state" | "error") && !seen.insert(name.clone()) {
            return Err(());
        }
        match name.as_str() {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => {
                error = true;
                forwarded.push((name, value));
            }
            _ => forwarded.push((name, value)),
        }
    }
    if code.is_some() == error {
        return Err(());
    }
    Ok(CallbackRequest {
        code,
        state: state.ok_or(())?,
        error,
        forwarded,
    })
}

fn scope_allowed(relay: &Relay, scope: &str) -> bool {
    let scopes: Vec<_> = scope.split(' ').collect();
    if scopes.is_empty() || scopes.iter().any(|scope| !valid_scope_token(scope)) {
        return false;
    }
    relay.allowed_scopes.as_ref().is_none_or(|allowed| {
        scopes
            .iter()
            .all(|scope| allowed.iter().any(|candidate| candidate == scope))
    })
}

fn parse_token_request(body: &[u8]) -> Result<TokenRequest, ()> {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
    let mut grant_type = None;
    let mut code = None;
    let mut refresh_token = None;
    let mut redirect_uri = None;
    let mut client_id = None;
    let mut client_secret = None;
    let mut code_verifier = None;
    let mut scope = None;
    let mut client_assertion_type = None;
    let mut client_assertion = None;
    let mut seen = std::collections::HashSet::new();

    for (name, value) in &pairs {
        let target = match name.as_str() {
            "grant_type" => &mut grant_type,
            "code" => &mut code,
            "refresh_token" => &mut refresh_token,
            "redirect_uri" => &mut redirect_uri,
            "client_id" => &mut client_id,
            "client_secret" => &mut client_secret,
            "code_verifier" => &mut code_verifier,
            "scope" => &mut scope,
            "client_assertion_type" => &mut client_assertion_type,
            "client_assertion" => &mut client_assertion,
            _ => continue,
        };
        if !seen.insert(name.as_str()) {
            return Err(());
        }
        *target = Some(value.clone());
    }

    Ok(TokenRequest {
        grant_type: grant_type.ok_or(())?,
        code,
        refresh_token,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier,
        scope,
        client_assertion_type,
        client_assertion,
        pairs,
    })
}

async fn authorize(
    state: &AppState,
    relay: &Relay,
    upstream: &Upstream,
    query: AuthorizeRequest,
) -> Response {
    let Some(redirect_value) = query.redirect_uri else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !relay.redirect_allowed(&redirect_value, state.cfg.allow_localhost_loopback) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query
        .code_challenge_method
        .as_deref()
        .is_some_and(|m| m != "S256")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query.code_challenge.is_none() && query.code_challenge_method.is_some() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if matches!(relay.client_auth, ClientAuth::Public) && query.code_challenge.is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query
        .code_challenge
        .as_deref()
        .is_some_and(|challenge| !valid_pkce_challenge(challenge))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let scope = match query.scope {
        Some(scope) if scope_allowed(relay, &scope) => Some(scope),
        Some(_) => return StatusCode::BAD_REQUEST.into_response(),
        None if relay.scopes.is_empty() => None,
        None => Some(relay.scopes.join(" ")),
    };
    let endpoints = match resolve_endpoints(state, upstream).await {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let verifier = random_urlsafe(64);
    let flow = FlowEnvelope {
        relay_key: relay.key.to_string(),
        app_redirect_uri: redirect_value,
        app_state: query.state,
        upstream_pkce_verifier: verifier.clone(),
        client_code_challenge_method: query.code_challenge.as_ref().map(|_| "S256".to_owned()),
        client_code_challenge: query.code_challenge,
        id_token_nonce: query.id_token_nonce,
        issued_at: unix_now(),
        nonce: random_array(),
    };
    let sealed = match seal_postcard(state, &upstream.key, &flow) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let callback = callback_url(&state.cfg.public_url, &upstream.key);
    let mut authorization_endpoint = endpoints.authorization_endpoint;
    {
        let mut params = authorization_endpoint.query_pairs_mut();
        params
            .append_pair("response_type", "code")
            .append_pair("client_id", &upstream.client_id)
            .append_pair("redirect_uri", callback.as_str())
            .append_pair("state", &sealed)
            .append_pair("code_challenge", &pkce_challenge(&verifier))
            .append_pair("code_challenge_method", "S256");
        if let Some(scope) = scope {
            params.append_pair("scope", &scope);
        }
        params.extend_pairs(query.forwarded);
    }
    found(authorization_endpoint.as_str())
}

async fn callback(state: &AppState, upstream: &Upstream, query: CallbackRequest) -> Response {
    let flow = match unseal_postcard::<FlowEnvelope>(state, &upstream.key, &query.state) {
        Ok(value) if fresh(value.issued_at, FLOW_TTL) => value,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let relay_key = match ResourceKey::new(&flow.relay_key) {
        Ok(key) => key,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let relay = match state.resolver.resolve_relay(&relay_key).await {
        Ok(Some(relay)) if relay.upstream == upstream.key && relay.validate().is_ok() => relay,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !relay.redirect_allowed(&flow.app_redirect_uri, state.cfg.allow_localhost_loopback) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut redirect = flow.app_redirect_uri.clone();
    if query.error {
        append_query_pairs(&mut redirect, &query.forwarded);
        if let Some(app_state) = flow.app_state {
            append_query_pairs(&mut redirect, &[("state".into(), app_state)]);
        }
        return found(&redirect);
    }
    let Some(code) = query.code else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let endpoints = match resolve_endpoints(state, upstream).await {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let callback = callback_url(&state.cfg.public_url, &upstream.key);
    let upstream_response = match state
        .cfg
        .http
        .post(endpoints.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", upstream.client_id.as_str()),
            ("client_secret", upstream.client_secret.expose()),
            ("redirect_uri", callback.as_str()),
            ("code_verifier", flow.upstream_pkce_verifier.as_str()),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let status = upstream_response.status().as_u16();
    let content_type = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let body = match upstream_response.bytes().await {
        Ok(body) => body.to_vec(),
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let envelope = CodeEnvelope {
        relay_key: relay.key.to_string(),
        envelope_id: random_array(),
        issued_at: unix_now(),
        redirect_uri: flow.app_redirect_uri,
        client_code_challenge: flow.client_code_challenge,
        id_token_nonce: flow.id_token_nonce,
        upstream_response: StoredResponse {
            status,
            content_type,
            body,
        },
    };
    let sealed = match seal_postcard(state, &relay.key, &envelope) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    if sealed.len() > 4096 {
        tracing::warn!(relay = %relay.key, size = sealed.len(), "sealed authorization code may exceed URL limits");
    }
    append_query_pairs(&mut redirect, &[("code".into(), sealed)]);
    append_query_pairs(&mut redirect, &query.forwarded);
    if let Some(app_state) = flow.app_state {
        append_query_pairs(&mut redirect, &[("state".into(), app_state)]);
    }
    found(&redirect)
}

fn append_query_pairs(url: &mut String, pairs: &[(String, String)]) {
    if pairs.is_empty() {
        return;
    }
    if !url.contains('?') {
        url.push('?');
    } else if !url.ends_with(['?', '&']) {
        url.push('&');
    }
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    url.push_str(&encoded);
}

async fn token(
    state: &AppState,
    relay: &Relay,
    upstream: &Upstream,
    request: Request<Body>,
) -> Response {
    let origin = allowed_cors_origin(relay, request.headers(), state.cfg.allow_localhost_loopback);
    let bytes = match axum::body::to_bytes(request.into_body(), 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return with_cors(
                oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "invalid body"),
                origin,
            )
        }
    };
    let form = match parse_token_request(&bytes) {
        Ok(form) => form,
        Err(_) => {
            return with_cors(
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "invalid form body",
                ),
                origin,
            )
        }
    };
    let auth_result = authenticate(state, relay, upstream, &form).await;
    if auth_result.is_err() {
        return with_cors(
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            ),
            origin,
        );
    }
    let response = match form.grant_type.as_str() {
        "authorization_code" => exchange_sealed_code(state, relay, upstream, &form).await,
        "refresh_token" => refresh(state, relay, upstream, &form).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "unsupported grant_type",
        ),
    };
    with_cors(response, origin)
}

async fn exchange_sealed_code(
    state: &AppState,
    relay: &Relay,
    upstream: &Upstream,
    form: &TokenRequest,
) -> Response {
    let Some(code) = &form.code else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required",
        );
    };
    let envelope = match unseal_postcard::<CodeEnvelope>(state, &relay.key, code) {
        Ok(value) if value.relay_key == relay.key.as_str() && fresh(value.issued_at, CODE_TTL) => {
            value
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid or expired code",
            )
        }
    };
    if form.redirect_uri.as_deref() != Some(envelope.redirect_uri.as_str()) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match",
        );
    }
    if let Some(expected) = &envelope.client_code_challenge {
        let Some(verifier) = &form.code_verifier else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "code_verifier is required",
            );
        };
        if !valid_pkce_verifier(verifier) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid code_verifier",
            );
        }
        if !constant_eq(expected.as_bytes(), pkce_challenge(verifier).as_bytes()) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            );
        }
    } else if matches!(relay.client_auth, ClientAuth::Public) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE challenge is missing",
        );
    }
    let validation = validate_required_id_token_claims(
        state,
        relay,
        upstream,
        &envelope.upstream_response,
        envelope.id_token_nonce.as_deref(),
    )
    .await;
    if validation == Err(IdTokenValidationError::Unavailable) {
        return oauth_error(
            StatusCode::BAD_GATEWAY,
            "server_error",
            "ID token validation is unavailable",
        );
    }
    if let Some(cache) = &state.cfg.replay_cache {
        let id = URL_SAFE_NO_PAD.encode(envelope.envelope_id);
        match cache.first_use(&id, Duration::from_secs(CODE_TTL)).await {
            Ok(true) => {}
            _ => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "code was already used",
                )
            }
        }
    }
    if validation == Err(IdTokenValidationError::Rejected) {
        return required_claims_error();
    }
    stored_response(envelope.upstream_response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdTokenValidationError {
    Rejected,
    Unavailable,
}

async fn validate_required_id_token_claims(
    state: &AppState,
    relay: &Relay,
    upstream: &Upstream,
    response: &StoredResponse,
    expected_nonce: Option<&str>,
) -> Result<(), IdTokenValidationError> {
    if relay.required_id_token_claims.is_empty()
        || !StatusCode::from_u16(response.status).is_ok_and(|status| status.is_success())
    {
        return Ok(());
    }

    let token_response: Value =
        serde_json::from_slice(&response.body).map_err(|_| IdTokenValidationError::Rejected)?;
    let id_token = token_response
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or(IdTokenValidationError::Rejected)?;
    let header = decode_header(id_token).map_err(|_| IdTokenValidationError::Rejected)?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        return Err(IdTokenValidationError::Rejected);
    }

    let jwks_uri = resolve_jwks_uri(state, upstream)
        .await
        .map_err(|_| IdTokenValidationError::Unavailable)?
        .ok_or(IdTokenValidationError::Unavailable)?;
    let value = cached_json(state, &jwks_uri, JWKS_TTL)
        .await
        .map_err(|_| IdTokenValidationError::Unavailable)?;
    let set: JwkSet =
        serde_json::from_value(value).map_err(|_| IdTokenValidationError::Unavailable)?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => set
            .keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid)),
        None if set.keys.len() == 1 => set.keys.first(),
        _ => None,
    }
    .ok_or(IdTokenValidationError::Rejected)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| IdTokenValidationError::Rejected)?;
    let issuer = issuer_identifier(&upstream.issuer_url);
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer.as_str()]);
    validation.set_audience(&[upstream.client_id.as_str()]);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
    validation.validate_nbf = true;
    let claims = decode::<Value>(id_token, &key, &validation)
        .map_err(|_| IdTokenValidationError::Rejected)?
        .claims;

    let issued_at = claims.get("iat").and_then(Value::as_u64);
    if !claims
        .get("sub")
        .and_then(Value::as_str)
        .is_some_and(|subject| !subject.is_empty())
        || issued_at.is_none_or(|issued_at| issued_at > unix_now() + ID_TOKEN_CLOCK_SKEW)
        || expected_nonce
            .is_some_and(|expected| claims.get("nonce").and_then(Value::as_str) != Some(expected))
        || !valid_authorized_party(&claims, &upstream.client_id)
        || !valid_access_token_hash(&claims, &token_response, header.alg)
    {
        return Err(IdTokenValidationError::Rejected);
    }

    if relay
        .required_id_token_claims
        .iter()
        .all(|(name, expected)| claims.get(name).and_then(Value::as_str) == Some(expected))
    {
        Ok(())
    } else {
        Err(IdTokenValidationError::Rejected)
    }
}

fn issuer_identifier(url: &Url) -> String {
    if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        url.as_str().trim_end_matches('/').to_owned()
    } else {
        url.to_string()
    }
}

fn valid_authorized_party(claims: &Value, client_id: &str) -> bool {
    let multiple_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1);
    match claims.get("azp") {
        Some(value) => value.as_str() == Some(client_id),
        None => !multiple_audiences,
    }
}

fn valid_access_token_hash(claims: &Value, token_response: &Value, algorithm: Algorithm) -> bool {
    let Some(actual) = claims.get("at_hash") else {
        return true;
    };
    let Some(actual) = actual.as_str() else {
        return false;
    };
    let Some(access_token) = token_response.get("access_token").and_then(Value::as_str) else {
        return false;
    };
    let expected = match algorithm {
        Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {
            let digest = Sha256::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        Algorithm::RS384 | Algorithm::PS384 | Algorithm::ES384 => {
            let digest = Sha384::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        Algorithm::RS512 | Algorithm::PS512 => {
            let digest = Sha512::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        _ => return false,
    };
    constant_eq(actual.as_bytes(), expected.as_bytes())
}

async fn refresh(
    state: &AppState,
    relay: &Relay,
    upstream: &Upstream,
    form: &TokenRequest,
) -> Response {
    if form.refresh_token.is_none() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    }
    if form
        .scope
        .as_deref()
        .is_some_and(|scope| !scope_allowed(relay, scope))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope is not allowed",
        );
    }
    let endpoints = match resolve_endpoints(state, upstream).await {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let mut upstream_form: Vec<_> = form
        .pairs
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "client_id" | "client_secret" | "client_assertion_type" | "client_assertion"
            )
        })
        .cloned()
        .collect();
    upstream_form.push(("client_id".into(), upstream.client_id.clone()));
    upstream_form.push((
        "client_secret".into(),
        upstream.client_secret.expose().to_owned(),
    ));
    match state
        .cfg
        .http
        .post(endpoints.token_endpoint)
        .form(&upstream_form)
        .send()
        .await
    {
        Ok(response) => proxy_response(response).await,
        Err(_) => oauth_error(
            StatusCode::BAD_GATEWAY,
            "server_error",
            "upstream request failed",
        ),
    }
}

async fn authenticate(
    state: &AppState,
    relay: &Relay,
    upstream: &Upstream,
    form: &TokenRequest,
) -> Result<(), ()> {
    match &relay.client_auth {
        ClientAuth::UpstreamClient => {
            let id = form.client_id.as_deref().unwrap_or_default();
            let secret = form.client_secret.as_deref().unwrap_or_default();
            if constant_eq(id.as_bytes(), upstream.client_id.as_bytes())
                & constant_eq(
                    secret.as_bytes(),
                    upstream.client_secret.expose().as_bytes(),
                )
            {
                Ok(())
            } else {
                Err(())
            }
        }
        ClientAuth::Public => {
            if form.client_secret.is_none()
                && form.client_assertion_type.is_none()
                && form.client_assertion.is_none()
            {
                Ok(())
            } else {
                Err(())
            }
        }
        ClientAuth::ClientSecret {
            client_id,
            client_secret,
        } => {
            let id = form.client_id.as_deref().unwrap_or_default();
            let secret = form.client_secret.as_deref().unwrap_or_default();
            if constant_eq(id.as_bytes(), client_id.as_bytes())
                & constant_eq(secret.as_bytes(), client_secret.expose().as_bytes())
            {
                Ok(())
            } else {
                Err(())
            }
        }
        ClientAuth::PrivateKeyJwt {
            client_id,
            issuer,
            subject,
            jwks,
        } => {
            if form.client_assertion_type.as_deref()
                != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                || form.client_id.as_deref() != Some(client_id)
            {
                return Err(());
            }
            let assertion = form.client_assertion.as_deref().ok_or(())?;
            verify_private_key_jwt(
                state,
                relay,
                issuer.as_deref().unwrap_or(client_id),
                subject.as_deref().unwrap_or(client_id),
                jwks.as_ref(),
                assertion,
            )
            .await
        }
    }
}

async fn verify_private_key_jwt(
    state: &AppState,
    relay: &Relay,
    issuer: &str,
    subject: &str,
    source: Option<&ClientJwks>,
    assertion: &str,
) -> Result<(), ()> {
    let value = match source {
        Some(ClientJwks::Inline(value)) => value.clone(),
        Some(ClientJwks::Url(url)) => cached_json(state, url, JWKS_TTL).await.map_err(|_| ())?,
        None => {
            let url = Url::parse(issuer).map_err(|_| ())?;
            if !crate::model::valid_discovery_url(&url) {
                return Err(());
            }
            let doc = cached_json(state, &discovery_url(&url), DISCOVERY_TTL)
                .await
                .map_err(|_| ())?;
            if doc.get("issuer").and_then(Value::as_str) != Some(issuer) {
                return Err(());
            }
            let jwks_url = url_field(&doc, "jwks_uri").ok_or(())?;
            if !crate::model::valid_discovery_url(&jwks_url) {
                return Err(());
            }
            cached_json(state, &jwks_url, JWKS_TTL)
                .await
                .map_err(|_| ())?
        }
    };
    let set: JwkSet = serde_json::from_value(value).map_err(|_| ())?;
    let header = decode_header(assertion).map_err(|_| ())?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    ) {
        return Err(());
    }
    let jwk = match header.kid.as_deref() {
        Some(kid) => set
            .keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid)),
        None if set.keys.len() == 1 => set.keys.first(),
        _ => None,
    }
    .ok_or(())?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| ())?;
    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false;
    validation.validate_nbf = true;
    let claims = decode::<Value>(assertion, &key, &validation)
        .map_err(|_| ())?
        .claims;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer)
        || claims.get("sub").and_then(Value::as_str) != Some(subject)
    {
        return Err(());
    }
    for name in ["iat", "nbf"] {
        if let Some(time) = claims.get(name) {
            if time.as_u64().ok_or(())? > unix_now().saturating_add(validation.leeway) {
                return Err(());
            }
        }
    }
    let audience = token_url(&state.cfg.public_url, &relay.key).to_string();
    let aud_ok = claims.get("aud").is_some_and(|aud| match aud {
        Value::String(value) => value == &audience,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(&audience)),
        _ => false,
    });
    aud_ok.then_some(()).ok_or(())
}

async fn discovery(state: &AppState, relay: &Relay, upstream: &Upstream) -> Response {
    let discovery = discovery_url(&upstream.issuer_url);
    let mut doc = if !needs_endpoint_discovery(upstream) {
        json!({})
    } else {
        match cached_json(state, &discovery, DISCOVERY_TTL).await {
            Ok(value) => value,
            Err(status) => return status.into_response(),
        }
    };
    let endpoints = match resolve_endpoints_from_doc(upstream, &doc) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let base = relay_base_url(&state.cfg.public_url, &relay.key);
    let issuer = doc
        .get("issuer")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let issuer = &upstream.issuer_url;
            if issuer.path() == "/" {
                issuer.as_str().trim_end_matches('/').to_owned()
            } else {
                issuer.to_string()
            }
        });
    doc["issuer"] = Value::String(issuer);
    doc["authorization_endpoint"] = Value::String(base.join("authorize").unwrap().to_string());
    doc["token_endpoint"] = Value::String(base.join("token").unwrap().to_string());
    if let Some(jwks_uri) = endpoints.jwks_uri {
        doc["jwks_uri"] = Value::String(jwks_uri.to_string());
    } else if let Some(object) = doc.as_object_mut() {
        object.remove("jwks_uri");
    }
    Json(doc).into_response()
}

async fn jwks(state: &AppState, upstream: &Upstream) -> Response {
    let url = match resolve_jwks_uri(state, upstream).await {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let Some(url) = url else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match cached_json(state, &url, JWKS_TTL).await {
        Ok(value) => Json(value).into_response(),
        Err(status) => status.into_response(),
    }
}

struct ResolvedEndpoints {
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Option<Url>,
}

async fn resolve_endpoints(
    state: &AppState,
    upstream: &Upstream,
) -> Result<ResolvedEndpoints, StatusCode> {
    if upstream.authorization_endpoint.is_some() && upstream.token_endpoint.is_some() {
        return resolve_endpoints_from_doc(upstream, &json!({}));
    }
    let doc = cached_json(state, &discovery_url(&upstream.issuer_url), DISCOVERY_TTL).await?;
    resolve_endpoints_from_doc(upstream, &doc)
}

async fn resolve_jwks_uri(
    state: &AppState,
    upstream: &Upstream,
) -> Result<Option<Url>, StatusCode> {
    if upstream.jwks_uri.is_some() {
        return Ok(upstream.jwks_uri.clone());
    }
    let doc = cached_json(state, &discovery_url(&upstream.issuer_url), DISCOVERY_TTL).await?;
    Ok(url_field(&doc, "jwks_uri"))
}

fn needs_endpoint_discovery(upstream: &Upstream) -> bool {
    upstream.authorization_endpoint.is_none()
        || upstream.token_endpoint.is_none()
        || upstream.jwks_uri.is_none()
}

fn resolve_endpoints_from_doc(
    upstream: &Upstream,
    doc: &Value,
) -> Result<ResolvedEndpoints, StatusCode> {
    let authorization_endpoint = upstream
        .authorization_endpoint
        .clone()
        .or_else(|| url_field(doc, "authorization_endpoint"))
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let token_endpoint = upstream
        .token_endpoint
        .clone()
        .or_else(|| url_field(doc, "token_endpoint"))
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let jwks_uri = upstream
        .jwks_uri
        .clone()
        .or_else(|| url_field(doc, "jwks_uri"));
    Ok(ResolvedEndpoints {
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
    })
}

fn url_field(doc: &Value, name: &str) -> Option<Url> {
    doc.get(name)
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok())
}

async fn cached_json(state: &AppState, url: &Url, ttl: Duration) -> Result<Value, StatusCode> {
    let key = url.to_string();
    {
        let cache = state.cache.lock().await;
        if let Some(entry) = cache.get(&key) {
            if entry.fetched.elapsed() < ttl {
                return Ok(entry.value.clone());
            }
        }
    }
    let response = state
        .cfg
        .http
        .get(url.clone())
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !response.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let value: Value = response.json().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    state.cache.lock().await.insert(
        key,
        CachedJson {
            fetched: std::time::Instant::now(),
            value: value.clone(),
        },
    );
    Ok(value)
}

async fn proxy_response(response: reqwest::Response) -> Response {
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .header(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if let Some(content_type) = content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response.body(Body::from(body)).unwrap()
}

fn stored_response(stored: StoredResponse) -> Response {
    let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .header(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if let Some(content_type) = stored.content_type {
        if let Ok(value) = HeaderValue::from_str(&content_type) {
            response = response.header(header::CONTENT_TYPE, value);
        }
    }
    response.body(Body::from(stored.body)).unwrap()
}

fn preflight(relay: &Relay, headers: &HeaderMap, allow_localhost_loopback: bool) -> Response {
    let origin = allowed_cors_origin(relay, headers, allow_localhost_loopback);
    if origin.is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    with_cors(StatusCode::NO_CONTENT.into_response(), origin)
}

fn allowed_cors_origin(
    relay: &Relay,
    headers: &HeaderMap,
    allow_localhost_loopback: bool,
) -> Option<HeaderValue> {
    let value = headers.get(header::ORIGIN)?;
    let url = Url::parse(value.to_str().ok()?).ok()?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    if relay.cors_origin_allowed(&url, allow_localhost_loopback) {
        Some(value.clone())
    } else {
        None
    }
}

fn with_cors(mut response: Response, origin: Option<HeaderValue>) -> Response {
    if let Some(origin) = origin {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    response
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn required_claims_error() -> Response {
    let mut response = oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "Identity does not satisfy required ID-token claims.",
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn seal_postcard<T: Serialize>(
    state: &AppState,
    key: &ResourceKey,
    value: &T,
) -> Result<String, StatusCode> {
    let bytes = postcard::to_stdvec(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .cfg
        .sealer
        .seal(&bytes, key.as_str().as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn unseal_postcard<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    key: &ResourceKey,
    value: &str,
) -> Result<T, ()> {
    let bytes = state
        .cfg
        .sealer
        .unseal(value, key.as_str().as_bytes())
        .map_err(|_| ())?;
    postcard::from_bytes(&bytes).map_err(|_| ())
}

fn relay_base_url(public_url: &Url, key: &ResourceKey) -> Url {
    let mut url = public_url.clone();
    url.set_path(&format!(
        "{}/relay/{}/",
        public_url.path().trim_end_matches('/'),
        key
    ));
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn callback_url(public_url: &Url, key: &ResourceKey) -> Url {
    let mut url = public_url.clone();
    url.set_path(&format!(
        "{}/upstream/{}/callback",
        public_url.path().trim_end_matches('/'),
        key
    ));
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn public_route_pattern(public_url: &Url) -> String {
    format!("{}/{{*path}}", public_url.path().trim_end_matches('/'))
}

fn token_url(public_url: &Url, key: &ResourceKey) -> Url {
    relay_base_url(public_url, key).join("token").unwrap()
}

fn discovery_url(issuer: &Url) -> Url {
    let mut issuer = issuer.clone();
    issuer.set_path(&format!(
        "{}/.well-known/openid-configuration",
        issuer.path().trim_end_matches('/')
    ));
    issuer.set_query(None);
    issuer.set_fragment(None);
    issuer
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn valid_pkce_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_pkce_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn random_urlsafe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut value = [0_u8; N];
    rand::rng().fill_bytes(&mut value);
    value
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fresh(issued_at: u64, ttl: u64) -> bool {
    let now = unix_now();
    issued_at <= now.saturating_add(30) && now.saturating_sub(issued_at) <= ttl
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s256_matches_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn path_strategies_are_exact() {
        assert!(parse_path("relay/google/token", &KeyStrategy::SingleSegment).is_some());
        assert!(parse_path(
            "relay/project/ext/.well-known/openid-configuration",
            &KeyStrategy::TwoSegment
        )
        .is_some());
        assert!(parse_path("relay/project/ext/token", &KeyStrategy::SingleSegment).is_none());
        assert!(parse_path("upstream/google/callback", &KeyStrategy::SingleSegment).is_some());
        assert!(parse_path("relay/google/callback", &KeyStrategy::SingleSegment).is_none());
    }

    #[test]
    fn constant_comparison_requires_equal_lengths() {
        assert!(constant_eq(b"secret", b"secret"));
        assert!(!constant_eq(b"secret", b"secrex"));
        assert!(!constant_eq(b"secret", b"secret-long"));
    }

    #[test]
    fn pkce_values_follow_rfc_7636_lengths_and_alphabet() {
        assert!(valid_pkce_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!valid_pkce_challenge("short"));
        assert!(valid_pkce_verifier(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
        assert!(!valid_pkce_verifier("short"));
    }
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod integration_tests;
