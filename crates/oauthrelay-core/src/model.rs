use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
};
use url::{Host, Url};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceKey(String);

impl ResourceKey {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('/')
            || value.ends_with('/')
            || value.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
        {
            return Err(
                "must contain non-empty URL-safe path segments other than `.` and `..`".into(),
            );
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ResourceKey {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Origin(Url);

impl Origin {
    pub fn parse(value: &str) -> Result<Self, String> {
        let url = Url::parse(value).map_err(|e| e.to_string())?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err("must be an http(s) origin".into());
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err("must contain only scheme, host, and optional port".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("must not contain user information".into());
        }
        Ok(Self(url))
    }

    pub fn url(&self) -> &Url {
        &self.0
    }

    pub fn matches(&self, other: &Url) -> bool {
        same_origin(&self.0, other)
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Default, Eq, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Upstream {
    pub key: ResourceKey,
    pub issuer_url: Url,
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub client_id: String,
    pub client_secret: SecretString,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

/// How the upstream client authenticates at the provider token endpoint.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// `client_id` and `client_secret` are form fields in the request body.
    #[default]
    ClientSecretPost,
    /// The credentials travel in an HTTP Basic `Authorization` header and not in the body.
    ClientSecretBasic,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Relay {
    pub key: ResourceKey,
    pub upstream: ResourceKey,
    /// Opaque identity of this incarnation of the relay, bound into every refresh-token handle
    /// it issues (`sealed` and `rotating`). Set it to a value that changes when the relay is
    /// deleted and recreated under the same key, such as the creation timestamp or unique id of
    /// the record that defines it, so a recreated relay does not accept its predecessor's
    /// handles. Changing it signs out every user holding a handle. `None` binds nothing beyond
    /// the key; the file and SSM providers leave it unset, and the Kubernetes provider sets the
    /// Relay resource's `metadata.uid`. Resource documents cannot set it.
    #[serde(default)]
    pub generation: Option<String>,
    pub client_auth: ClientAuth,
    pub scopes: Vec<String>,
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub required_id_token_claims: HashMap<String, String>,
    #[serde(default)]
    pub id_token_policy: Option<crate::IdTokenPolicy>,
    #[serde(default)]
    pub refresh_tokens: RefreshTokens,
    pub redirect_policy: Vec<RedirectMatcher>,
}

/// Default time an already-rotated handle keeps answering with its recorded successor.
pub const DEFAULT_GRACE_PERIOD_SECONDS: u64 = 30;
/// Longest accepted grace period (five minutes).
pub const MAX_GRACE_PERIOD_SECONDS: u64 = 5 * 60;
/// Default absolute lifetime of a rotating refresh-token family (30 days).
pub const DEFAULT_MAX_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Longest accepted family lifetime (ten years); it only guards against arithmetic overflow and
/// absurd TTLs.
pub const MAX_MAX_LIFETIME_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;

/// How a relay hands upstream refresh tokens to downstream clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct RefreshTokens {
    pub mode: RefreshTokenMode,
    /// `rotating` only: how long a rotated handle still answers with its recorded successor.
    pub grace_period_seconds: u64,
    /// `rotating` only: absolute lifetime of a family, measured from the code grant that created it.
    pub max_lifetime_seconds: u64,
}

impl Default for RefreshTokens {
    fn default() -> Self {
        Self {
            mode: RefreshTokenMode::default(),
            grace_period_seconds: DEFAULT_GRACE_PERIOD_SECONDS,
            max_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS,
        }
    }
}

impl RefreshTokens {
    /// Rejects rotation parameters outside their bounds.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_GRACE_PERIOD_SECONDS).contains(&self.grace_period_seconds) {
            return Err(format!(
                "refresh_tokens.grace_period_seconds must be between 1 and {MAX_GRACE_PERIOD_SECONDS}"
            ));
        }
        if self.max_lifetime_seconds < self.grace_period_seconds
            || self.max_lifetime_seconds > MAX_MAX_LIFETIME_SECONDS
        {
            return Err(format!(
                "refresh_tokens.max_lifetime_seconds must be between grace_period_seconds and {MAX_MAX_LIFETIME_SECONDS}"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTokenMode {
    /// The upstream refresh token is returned to the client unchanged.
    #[default]
    Passthrough,
    /// Token responses carry a sealed handle that only this relay can open.
    Sealed,
    /// Token responses carry a single-use handle whose state lives in the transient store.
    Rotating,
}

/// Development-time widenings of redirect and CORS matching, set by the serving `RelayConfig`.
///
/// Every flag defaults to off, and a widening never applies unless its flag is on. Construct it
/// with `..Default::default()`, as in
/// `RedirectOptions { allow_http_origins: true, ..Default::default() }`, so flags added later
/// keep their off default without breaking the construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RedirectOptions {
    /// Loopback matchers also match the hosts `localhost` and `*.localhost` (RFC 6761 §6.3).
    pub allow_localhost_loopback: bool,
    /// `Origin` matchers may name and match `http://` origins.
    pub allow_http_origins: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub enum RedirectMatcher {
    /// One complete redirect URI, compared exactly.
    Uri(String),
    /// Every path and query at one origin. HTTPS, or HTTP when
    /// [`RedirectOptions::allow_http_origins`] is on.
    Origin(Origin),
    /// One exact path and query on an IP-literal loopback host, on any port.
    Loopback(String),
    /// Every path and query on an IP-literal loopback host, on any port.
    LoopbackOrigin(Origin),
}

impl RedirectMatcher {
    pub fn uri(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_exact_uri(&value)?;
        Ok(Self::Uri(value))
    }

    pub fn origin(value: &str) -> Result<Self, String> {
        let origin = Origin::parse(value)?;
        if origin.url().scheme() != "https" {
            return Err("must use https".into());
        }
        Ok(Self::Origin(origin))
    }

    /// An `http://` origin matcher. It matches only while
    /// [`RedirectOptions::allow_http_origins`] is on, and [`Relay::validate_for`] rejects it
    /// otherwise.
    pub fn http_origin(value: &str) -> Result<Self, String> {
        validate_raw_uri(value)?;
        let origin = Origin::parse(value)?;
        if origin.url().scheme() != "http" {
            return Err("must use http".into());
        }
        if !matches!(raw_path_and_query(value), Some("" | "/"))
            || !canonical_authority(value, origin.url())
        {
            return Err(
                "must be spelled canonically as http://host or http://host:port, without a path"
                    .into(),
            );
        }
        Ok(Self::Origin(origin))
    }

    pub fn loopback(value: &str) -> Result<Self, String> {
        validate_loopback_uri(value)?;
        Ok(Self::Loopback(value.to_owned()))
    }

    /// `http://127.0.0.1` or `http://[::1]`: any port, path, and query on that host.
    pub fn loopback_origin(value: &str) -> Result<Self, String> {
        let error = || {
            "must be http://127.0.0.1 or http://[::1] without a port, path, query, user information, or fragment"
                .to_owned()
        };
        validate_raw_uri(value)?;
        if !matches!(raw_path_and_query(value), Some("" | "/")) {
            return Err(error());
        }
        let origin = Origin::parse(value).map_err(|_| error())?;
        validate_loopback_origin(&origin).map_err(|_| error())?;
        if !canonical_authority(value, origin.url())
            || raw_authority(value).is_none_or(|(_, port)| port.is_some())
        {
            return Err(error());
        }
        Ok(Self::LoopbackOrigin(origin))
    }

    fn identity(&self) -> String {
        match self {
            Self::Uri(value) => format!("uri\0{value}"),
            Self::Origin(value) => format!("origin\0{}", value.url()),
            Self::Loopback(value) => format!("loopback\0{value}"),
            Self::LoopbackOrigin(value) => format!("loopback_origin\0{}", value.url()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ClientAuth {
    UpstreamClient,
    Public,
    ClientSecret {
        client_id: String,
        client_secret: SecretString,
    },
    PrivateKeyJwt {
        #[serde(default)]
        require_single_use: bool,
        client_id: String,
        #[serde(default)]
        issuer: Option<String>,
        #[serde(default)]
        subject: Option<String>,
        #[serde(default)]
        audience: Option<String>,
        #[serde(default)]
        jwks: Option<ClientJwks>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientJwks {
    Url(Url),
    Inline(serde_json::Value),
}

impl Upstream {
    pub fn validate(&self) -> Result<(), String> {
        for (field, url) in std::iter::once(("issuer_url", &self.issuer_url))
            .chain(
                self.authorization_endpoint
                    .as_ref()
                    .map(|url| ("authorization_endpoint", url)),
            )
            .chain(
                self.token_endpoint
                    .as_ref()
                    .map(|url| ("token_endpoint", url)),
            )
            .chain(self.jwks_uri.as_ref().map(|url| ("jwks_uri", url)))
        {
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(format!("{field} must be an absolute http(s) URL"));
            }
        }
        if self.client_id.is_empty() {
            return Err("client_id must not be empty".into());
        }
        if self.client_secret.expose().is_empty() {
            return Err("client_secret must not be empty".into());
        }
        Ok(())
    }
}

impl Relay {
    pub fn redirect_allowed(&self, redirect: &str, options: RedirectOptions) -> bool {
        if validate_raw_uri(redirect).is_err() {
            return false;
        }
        let Ok(url) = Url::parse(redirect) else {
            return false;
        };
        if !valid_redirect_url(&url) {
            return false;
        }
        self.redirect_policy.iter().any(|matcher| match matcher {
            RedirectMatcher::Uri(value) => validate_exact_uri(value).is_ok() && value == redirect,
            RedirectMatcher::Origin(origin) => {
                origin_permitted(origin, options)
                    && origin.matches(&url)
                    && (url.scheme() == "https" || canonical_authority(redirect, &url))
            }
            RedirectMatcher::Loopback(value) => Url::parse(value).is_ok_and(|base| {
                validate_loopback_uri(value).is_ok()
                    && url.scheme() == "http"
                    && loopback_host_matches(&base, &url, options.allow_localhost_loopback)
                    && canonical_authority(redirect, &url)
                    && raw_path_and_query(value)
                        .is_some_and(|tail| raw_path_and_query(redirect) == Some(tail))
            }),
            RedirectMatcher::LoopbackOrigin(base) => {
                validate_loopback_origin(base).is_ok()
                    && url.scheme() == "http"
                    && loopback_host_matches(base.url(), &url, options.allow_localhost_loopback)
                    && canonical_authority(redirect, &url)
            }
        })
    }

    pub fn cors_origin_allowed(&self, origin: &Url, options: RedirectOptions) -> bool {
        if !valid_origin_url(origin) {
            return false;
        }
        self.redirect_policy.iter().any(|matcher| match matcher {
            RedirectMatcher::Uri(value) => {
                validate_exact_uri(value).is_ok()
                    && Url::parse(value).is_ok_and(|redirect| same_origin(&redirect, origin))
            }
            RedirectMatcher::Origin(allowed) => {
                origin_permitted(allowed, options) && allowed.matches(origin)
            }
            RedirectMatcher::Loopback(value) => Url::parse(value).is_ok_and(|base| {
                validate_loopback_uri(value).is_ok()
                    && origin.scheme() == "http"
                    && loopback_host_matches(&base, origin, options.allow_localhost_loopback)
            }),
            RedirectMatcher::LoopbackOrigin(base) => {
                validate_loopback_origin(base).is_ok()
                    && origin.scheme() == "http"
                    && loopback_host_matches(base.url(), origin, options.allow_localhost_loopback)
            }
        })
    }

    /// Runtime validation: everything [`Relay::validate`] checks, plus the checks that depend on
    /// the serving [`RedirectOptions`]. A matcher that needs a widening `options` leaves off (an
    /// `http://` origin without `allow_http_origins`) fails here, so the relay fails loudly instead
    /// of silently rejecting those redirects. The router applies this to every resolved relay.
    pub fn validate_for(&self, options: RedirectOptions) -> Result<(), String> {
        self.validate()?;
        if !options.allow_http_origins {
            if let Some(origin) = self
                .redirect_policy
                .iter()
                .find_map(|matcher| match matcher {
                    RedirectMatcher::Origin(origin) if origin.url().scheme() != "https" => {
                        Some(origin)
                    }
                    _ => None,
                })
            {
                return Err(format!(
                    "redirect_policy origin {} uses http, which requires allow_http_origins (OAUTHRELAY_ALLOW_HTTP_ORIGINS)",
                    origin.url().origin().ascii_serialization()
                ));
            }
        }
        Ok(())
    }

    /// Structural validation only: checks that do not depend on how the relay is served. It does
    /// not consult [`RedirectOptions`], so an `http://` origin passes here; use
    /// [`Relay::validate_for`] to check a relay against the serving options.
    pub fn validate(&self) -> Result<(), String> {
        if self
            .required_id_token_claims
            .keys()
            .any(|claim| claim.is_empty())
        {
            return Err("required_id_token_claims must not contain an empty claim name".into());
        }
        if let Some(policy) = &self.id_token_policy {
            policy.validate()?;
        }
        self.refresh_tokens.validate()?;
        // RFC 9700 section 4.14.2: a public client's refresh tokens must be sender-constrained or
        // rotated, and the relay does not sender-constrain them.
        if matches!(self.client_auth, ClientAuth::Public)
            && self.refresh_tokens.mode != RefreshTokenMode::Rotating
        {
            return Err(
                "clientAuthentication.type: Public requires refreshTokens.mode: rotating, \
                because a public client's refresh tokens must be rotated; set refreshTokens.mode \
                to rotating, or authenticate the relying party with ClientSecret, UpstreamClient \
                or PrivateKeyJwt. rotating needs a transient store shared by every serving \
                instance (OAUTHRELAY_STORE, e.g. dynamodb or kubernetes); the default memory \
                store only suits a single instance"
                    .into(),
            );
        }
        let mut configured_scopes = HashSet::new();
        for scope in &self.scopes {
            if !valid_scope_token(scope) {
                return Err("scopes.default must contain valid RFC 6749 scope tokens".into());
            }
            if !configured_scopes.insert(scope.as_str()) {
                return Err("scopes.default must not contain duplicates".into());
            }
        }
        if let Some(allowed) = &self.allowed_scopes {
            let mut allowed_scopes = HashSet::new();
            for scope in allowed {
                if !valid_scope_token(scope) {
                    return Err("scopes.allowed must contain valid RFC 6749 scope tokens".into());
                }
                if !allowed_scopes.insert(scope.as_str()) {
                    return Err("scopes.allowed must not contain duplicates".into());
                }
            }
            if !configured_scopes.is_subset(&allowed_scopes) {
                return Err("scopes.default must be contained in scopes.allowed".into());
            }
        }
        if self.redirect_policy.is_empty() {
            return Err("redirect_policy must contain at least one matcher".into());
        }
        let mut redirects = HashSet::new();
        for matcher in &self.redirect_policy {
            match matcher {
                RedirectMatcher::Uri(value) => validate_exact_uri(value)?,
                // `Origin::parse` admits only http(s); `validate_for` gates http.
                RedirectMatcher::Origin(_) => {}
                RedirectMatcher::Loopback(value) => validate_loopback_uri(value)?,
                RedirectMatcher::LoopbackOrigin(value) => validate_loopback_origin(value)?,
            }
            if !redirects.insert(matcher.identity()) {
                return Err("redirect_policy must not contain duplicates".into());
            }
        }
        match &self.client_auth {
            ClientAuth::UpstreamClient | ClientAuth::Public => Ok(()),
            ClientAuth::ClientSecret {
                client_id,
                client_secret,
            } if client_id.is_empty() || client_secret.expose().is_empty() => {
                Err("clientAuthentication credentials must not be empty".into())
            }
            ClientAuth::PrivateKeyJwt { client_id, .. } if client_id.is_empty() => {
                Err("clientAuthentication.clientId must not be empty".into())
            }
            ClientAuth::PrivateKeyJwt {
                issuer,
                subject,
                audience,
                jwks,
                ..
            } => {
                if let Some(issuer) = issuer {
                    let url = Url::parse(issuer)
                        .map_err(|_| "clientAuthentication.issuer must be an absolute HTTPS URL")?;
                    if !valid_discovery_url(&url) {
                        return Err("clientAuthentication.issuer must use HTTPS (HTTP on loopback) without user information, query, or fragment".into());
                    }
                }
                if subject.as_ref().is_some_and(|value| value.is_empty()) {
                    return Err("clientAuthentication.subject must not be empty".into());
                }
                if audience.as_ref().is_some_and(|value| value.is_empty()) {
                    return Err("clientAuthentication.audience must not be empty".into());
                }
                match jwks {
                    None if issuer.is_none() => {
                        Err("clientAuthentication requires jwks or issuer discovery".into())
                    }
                    Some(ClientJwks::Url(url))
                        if !matches!(url.scheme(), "http" | "https")
                            || url.host_str().is_none() =>
                    {
                        Err("clientAuthentication.jwks must be an absolute http(s) URL".into())
                    }
                    Some(ClientJwks::Inline(value))
                        if !value
                            .get("keys")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|keys| !keys.is_empty()) =>
                    {
                        Err("clientAuthentication.jwks must contain a non-empty keys array".into())
                    }
                    _ => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }
}

pub(crate) fn valid_discovery_url(url: &Url) -> bool {
    (url.scheme() == "https" || (url.scheme() == "http" && is_ip_loopback(url)))
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn validate_exact_uri(value: &str) -> Result<(), String> {
    validate_raw_uri(value)?;
    let url = Url::parse(value).map_err(|error| error.to_string())?;
    if !valid_redirect_url(&url) {
        return Err("must be an absolute redirect URI without user information or fragment".into());
    }
    if url.scheme() == "https" || (url.scheme() == "http" && is_ip_loopback(&url)) {
        Ok(())
    } else {
        Err("must use https unless it targets an IP-literal loopback host".into())
    }
}

fn validate_loopback_uri(value: &str) -> Result<(), String> {
    validate_raw_uri(value)?;
    let url = Url::parse(value).map_err(|error| error.to_string())?;
    validate_loopback_base(&url)
}

fn validate_raw_uri(value: &str) -> Result<(), String> {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'\\')
    {
        return Err("must use an ASCII URI without whitespace or backslashes".into());
    }
    Ok(())
}

fn validate_loopback_base(url: &Url) -> Result<(), String> {
    if url.scheme() != "http"
        || !is_ip_loopback(url)
        || url.port().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(
            "must be an http URI on 127.0.0.1 or ::1 without a port, user information, or fragment"
                .into(),
        );
    }
    Ok(())
}

fn validate_loopback_origin(origin: &Origin) -> Result<(), String> {
    validate_loopback_base(origin.url())?;
    if origin.url().path() != "/" || origin.url().query().is_some() {
        return Err("loopback origin must not contain a path or query".into());
    }
    Ok(())
}

fn origin_permitted(origin: &Origin, options: RedirectOptions) -> bool {
    match origin.url().scheme() {
        "https" => true,
        "http" => options.allow_http_origins,
        _ => false,
    }
}

/// The raw host and optional port between `://` and the first `/`, `?`, or `#`. A bracketed host
/// keeps its brackets.
fn raw_authority(raw: &str) -> Option<(&str, Option<&str>)> {
    let rest = raw.split_once("://")?.1;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let (host, tail) = authority.split_at(close + 1);
        match tail {
            "" => Some((host, None)),
            tail => Some((host, Some(tail.strip_prefix(':')?))),
        }
    } else {
        Some(match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        })
    }
}

/// Whether `raw` spells its scheme, host, and port unambiguously as `url` parsed them, so lenient
/// parser forms never pass: `http:host`, `http:/host`, `http:///host`, empty user information,
/// shortened, octal, or hexadecimal IPv4 hosts, percent-encoded hosts, and zero-padded ports.
/// Scheme and host compare without regard to ASCII case. A bracketed IPv6 literal may use any
/// spelling of the parsed address, such as `[0:0:0:0:0:0:0:1]` for `[::1]`, and a port may be
/// the scheme's default spelled out, such as `:80`.
fn canonical_authority(raw: &str, url: &Url) -> bool {
    let Some((scheme, _)) = raw.split_once("://") else {
        return false;
    };
    let Some((host, port)) = raw_authority(raw) else {
        return false;
    };
    let host_matches = match url.host() {
        Some(Host::Ipv6(address)) => {
            host.strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .and_then(|literal| literal.parse::<Ipv6Addr>().ok())
                == Some(address)
        }
        Some(_) => url
            .host_str()
            .is_some_and(|parsed| host.eq_ignore_ascii_case(parsed)),
        None => false,
    };
    let port_matches = match port {
        None => url.port().is_none(),
        Some(port) => {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && (port == "0" || !port.starts_with('0'))
                && port.parse::<u16>().ok() == url.port_or_known_default()
        }
    };
    scheme.eq_ignore_ascii_case(url.scheme()) && host_matches && port_matches
}

fn valid_redirect_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn valid_origin_url(url: &Url) -> bool {
    valid_redirect_url(url) && url.path() == "/" && url.query().is_none()
}

fn is_ip_loopback(url: &Url) -> bool {
    matches!(
        url.host(),
        Some(Host::Ipv4(address)) if address == Ipv4Addr::LOCALHOST
    ) || matches!(url.host(), Some(Host::Ipv6(address)) if address.is_loopback())
}

fn loopback_host_matches(base: &Url, candidate: &Url, allow_localhost: bool) -> bool {
    base.host() == candidate.host()
        || (allow_localhost
            && matches!(candidate.host(), Some(Host::Domain(domain)) if is_localhost_name(domain)))
}

/// `localhost`, or a non-empty sequence of DNS labels ending in `.localhost` (RFC 6761 §6.3),
/// compared without regard to ASCII case. Empty labels and a trailing dot are rejected.
fn is_localhost_name(domain: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    if domain == "localhost" {
        return true;
    }
    domain.len() <= 253
        && domain.strip_suffix(".localhost").is_some_and(|labels| {
            !labels.is_empty()
                && labels.split('.').all(|label| {
                    (1..=63).contains(&label.len())
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                })
        })
}

fn raw_path_and_query(value: &str) -> Option<&str> {
    let authority = value.split_once("://")?.1;
    Some(
        authority
            .find(['/', '?'])
            .map_or("", |index| &authority[index..]),
    )
}

pub(crate) fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

pub(crate) fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            == b.host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        && a.port_or_known_default() == b.port_or_known_default()
}

pub type UpstreamMap = std::collections::HashMap<ResourceKey, Arc<Upstream>>;
pub type RelayMap = std::collections::HashMap<ResourceKey, Arc<Relay>>;

#[cfg(test)]
mod tests {
    use super::*;

    const OFF: RedirectOptions = RedirectOptions {
        allow_localhost_loopback: false,
        allow_http_origins: false,
    };
    const LOCALHOST: RedirectOptions = RedirectOptions {
        allow_localhost_loopback: true,
        allow_http_origins: false,
    };
    const HTTP_ORIGINS: RedirectOptions = RedirectOptions {
        allow_localhost_loopback: false,
        allow_http_origins: true,
    };
    const ALL: RedirectOptions = RedirectOptions {
        allow_localhost_loopback: true,
        allow_http_origins: true,
    };

    #[test]
    fn resource_keys_are_plain_path_segments() {
        for valid in ["google", "a/b", "a.b", "a-b_c", "...", "a/..b"] {
            assert!(ResourceKey::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "", "/", "a/", "/a", "a//b", ".", "..", "a/.", "a/../b", "./a", "a%2Fb", "a b",
        ] {
            assert!(ResourceKey::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn redirect_matchers_are_explicit_and_distinct() {
        let relay = Relay {
            key: ResourceKey::new("google").unwrap(),
            upstream: ResourceKey::new("google").unwrap(),
            generation: None,
            client_auth: ClientAuth::Public,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            id_token_policy: None,
            refresh_tokens: RefreshTokens {
                mode: RefreshTokenMode::Rotating,
                ..RefreshTokens::default()
            },
            redirect_policy: vec![
                RedirectMatcher::uri("https://exact.example/cb?channel=stable&next=%2Fhome")
                    .unwrap(),
                RedirectMatcher::origin("https://preview.example.com").unwrap(),
                RedirectMatcher::loopback("http://127.0.0.1/oauth/callback?source=cli").unwrap(),
                RedirectMatcher::loopback("http://[::1]/oauth/callback").unwrap(),
            ],
        };
        assert!(relay.redirect_allowed("https://exact.example/cb?channel=stable&next=%2Fhome", OFF));
        assert!(
            !relay.redirect_allowed("https://exact.example/cb?next=%2Fhome&channel=stable", OFF)
        );
        assert!(
            !relay.redirect_allowed("https://exact.example/cb?channel=stable&next=%2fhome", OFF)
        );
        assert!(relay.redirect_allowed("https://preview.example.com/any/path?x=1", OFF));
        assert!(!relay.redirect_allowed("https://preview.example.com:8443/any/path", OFF));
        assert!(relay.redirect_allowed("http://127.0.0.1:49152/oauth/callback?source=cli", OFF));
        assert!(relay.redirect_allowed("http://[::1]:49152/oauth/callback", OFF));
        assert!(!relay.redirect_allowed("http://localhost:49152/oauth/callback?source=cli", OFF));
        assert!(relay.redirect_allowed(
            "http://localhost:49152/oauth/callback?source=cli",
            LOCALHOST
        ));
        let normalized_path = Relay {
            redirect_policy: vec![
                RedirectMatcher::loopback("http://127.0.0.1/a/../callback").unwrap()
            ],
            ..relay.clone()
        };
        assert!(!normalized_path.redirect_allowed("http://127.0.0.1:49152/callback", OFF));
        // Any spelling of the IPv6 loopback address and an explicit default port are unambiguous.
        for spelled in [
            "http://[0:0:0:0:0:0:0:1]:49152/oauth/callback",
            "http://[::1]:80/oauth/callback",
        ] {
            assert!(relay.redirect_allowed(spelled, OFF), "{spelled}");
        }
        assert!(relay.redirect_allowed("http://127.0.0.1:80/oauth/callback?source=cli", OFF));
        for ambiguous in [
            "http://127.1:49152/oauth/callback?source=cli",
            "http://0x7f.0.0.1:49152/oauth/callback?source=cli",
            "http://127.0.0.1:080/oauth/callback?source=cli",
            "http://[::1]:049152/oauth/callback",
            "http:///127.0.0.1:49152/oauth/callback?source=cli",
        ] {
            assert!(!relay.redirect_allowed(ambiguous, LOCALHOST), "{ambiguous}");
        }
        for bad in [
            "http://127.0.0.1:49152\\evil/oauth/callback?source=cli",
            "http://127.0.0.1:49152\\@evil.test/oauth/callback?source=cli",
            "http:/127.0.0.1/oauth/callback?source=cli",
            "https://preview.example.com.evil.test/cb",
            "https://preview.example.com@evil.test/cb",
            "http://preview.example.com/cb",
            "javascript://localhost/x",
            "http://localhost.evil.test/cb",
            "https://user@preview.example.com/cb",
            "https://preview.example.com/cb#fragment",
        ] {
            assert!(!relay.redirect_allowed(bad, LOCALHOST), "{bad}");
        }
        assert!(relay.validate().is_ok());
    }

    #[test]
    fn public_relays_require_rotating_refresh_tokens() {
        let relay = |client_auth, mode| Relay {
            generation: None,
            key: ResourceKey::new("spa").unwrap(),
            upstream: ResourceKey::new("google").unwrap(),
            client_auth,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            id_token_policy: None,
            refresh_tokens: RefreshTokens {
                mode,
                ..RefreshTokens::default()
            },
            redirect_policy: vec![RedirectMatcher::uri("https://app.example/cb").unwrap()],
        };
        for mode in [RefreshTokenMode::Passthrough, RefreshTokenMode::Sealed] {
            let error = relay(ClientAuth::Public, mode).validate().unwrap_err();
            assert!(
                error.contains("Public requires refreshTokens.mode: rotating")
                    && error.contains("OAUTHRELAY_STORE"),
                "{error}"
            );
            for confidential in [
                ClientAuth::UpstreamClient,
                ClientAuth::ClientSecret {
                    client_id: "application".into(),
                    client_secret: SecretString::new("secret"),
                },
            ] {
                relay(confidential, mode).validate().unwrap();
            }
        }
        relay(ClientAuth::Public, RefreshTokenMode::Rotating)
            .validate()
            .unwrap();
    }

    #[test]
    fn redirect_matchers_enforce_transport_and_shape() {
        assert!(RedirectMatcher::uri("https://app.example/callback").is_ok());
        assert!(RedirectMatcher::uri("http://127.0.0.1:8080/callback").is_ok());
        assert!(RedirectMatcher::uri("http://app.example/callback").is_err());
        assert!(RedirectMatcher::uri("https://user@app.example/callback").is_err());
        assert!(RedirectMatcher::uri("https://app.example/callback#fragment").is_err());
        assert!(RedirectMatcher::origin("https://app.example").is_ok());
        assert!(RedirectMatcher::origin("http://app.example").is_err());
        assert!(RedirectMatcher::origin("https://app.example/callback").is_err());
        assert!(RedirectMatcher::loopback("http://[::1]/callback").is_ok());
        assert!(RedirectMatcher::loopback("http://127.0.0.1:8080/callback").is_err());
        assert!(RedirectMatcher::loopback("http://127.0.0.2/callback").is_err());
        assert!(RedirectMatcher::loopback("http://localhost/callback").is_err());
        assert!(RedirectMatcher::loopback("http://127.0.0.1/cb\\x").is_err());
        assert!(RedirectMatcher::uri("https://app.example/cb\\x").is_err());
    }

    #[test]
    fn cors_uses_matcher_origins_without_broadening_redirects() {
        let relay = Relay {
            key: ResourceKey::new("google").unwrap(),
            upstream: ResourceKey::new("google").unwrap(),
            generation: None,
            client_auth: ClientAuth::UpstreamClient,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            id_token_policy: None,
            refresh_tokens: RefreshTokens::default(),
            redirect_policy: vec![
                RedirectMatcher::uri("https://exact.example/cb").unwrap(),
                RedirectMatcher::origin("https://preview.example").unwrap(),
                RedirectMatcher::loopback("http://127.0.0.1/callback").unwrap(),
            ],
        };
        assert!(relay.cors_origin_allowed(&Url::parse("https://exact.example").unwrap(), OFF));
        assert!(!relay.redirect_allowed("https://exact.example/other", OFF));
        assert!(relay.cors_origin_allowed(&Url::parse("https://preview.example").unwrap(), OFF));
        assert!(relay.cors_origin_allowed(&Url::parse("http://127.0.0.1:49152").unwrap(), OFF));
        assert!(!relay.cors_origin_allowed(&Url::parse("http://localhost:49152").unwrap(), OFF));
        assert!(
            relay.cors_origin_allowed(&Url::parse("http://localhost:49152").unwrap(), LOCALHOST)
        );
    }

    fn relay_with(redirect_policy: Vec<RedirectMatcher>) -> Relay {
        Relay {
            generation: None,
            key: ResourceKey::new("dev").unwrap(),
            upstream: ResourceKey::new("google").unwrap(),
            client_auth: ClientAuth::UpstreamClient,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            id_token_policy: None,
            refresh_tokens: RefreshTokens::default(),
            redirect_policy,
        }
    }

    fn cors(relay: &Relay, origin: &str, options: RedirectOptions) -> bool {
        relay.cors_origin_allowed(&Url::parse(origin).unwrap(), options)
    }

    #[test]
    fn loopback_origin_matcher_shape() {
        for good in [
            "http://127.0.0.1",
            "http://127.0.0.1/",
            "http://[::1]",
            "http://[::1]/",
            "http://[0:0:0:0:0:0:0:1]",
        ] {
            assert!(RedirectMatcher::loopback_origin(good).is_ok(), "{good}");
        }
        for bad in [
            "https://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:80",
            "http://[::1]:80",
            "http://127.1",
            "http://127.0.0.1/callback",
            "http://127.0.0.1/.",
            "http://127.0.0.1/a/..",
            "http://127.0.0.1//",
            "http://127.0.0.1?",
            "http://127.0.0.1?x=1",
            "http://127.0.0.1#",
            "http://127.0.0.1#x",
            "http://user@127.0.0.1",
            "http://@127.0.0.1",
            "http://127.0.0.2",
            "http://localhost",
            "http://app.localhost",
            "http://example.com",
            "http://127.0.0.1\\",
            "http:/127.0.0.1",
            "http:127.0.0.1",
            "ws://127.0.0.1",
            "file:///tmp",
            " http://127.0.0.1",
        ] {
            assert!(RedirectMatcher::loopback_origin(bad).is_err(), "{bad}");
        }
        let duplicate = relay_with(vec![
            RedirectMatcher::loopback_origin("http://127.0.0.1").unwrap(),
            RedirectMatcher::loopback_origin("http://127.0.0.1/").unwrap(),
        ]);
        assert!(duplicate
            .validate()
            .unwrap_err()
            .contains("must not contain duplicates"));
        let duplicate = relay_with(vec![
            RedirectMatcher::loopback_origin("http://[::1]").unwrap(),
            RedirectMatcher::loopback_origin("http://[0:0:0:0:0:0:0:1]").unwrap(),
        ]);
        assert!(duplicate
            .validate()
            .unwrap_err()
            .contains("must not contain duplicates"));
        let distinct = relay_with(vec![
            RedirectMatcher::loopback_origin("http://127.0.0.1").unwrap(),
            RedirectMatcher::loopback("http://127.0.0.1/").unwrap(),
        ]);
        assert!(distinct.validate().is_ok());
    }

    #[test]
    fn loopback_origin_matches_any_port_path_and_query() {
        let relay = relay_with(vec![
            RedirectMatcher::loopback_origin("http://127.0.0.1").unwrap(),
            RedirectMatcher::loopback_origin("http://[::1]").unwrap(),
        ]);
        assert!(relay.validate().is_ok());
        for good in [
            "http://127.0.0.1",
            "http://127.0.0.1/",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:49152/oauth/callback",
            "http://127.0.0.1:49152/any/other/path?x=1&y=%2F",
            "http://127.0.0.1:1/?",
            "http://127.0.0.1?next=%2F",
            "HTTP://127.0.0.1:8080/cb",
            "http://127.0.0.1:80/cb",
            "http://[::1]:49152/auth/callback?state=x",
            "http://[0:0:0:0:0:0:0:1]:49152/cb",
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]:49152/cb",
            "http://[::0:1]/cb",
            "http://[::1]:80/cb",
        ] {
            assert!(relay.redirect_allowed(good, OFF), "{good}");
        }
        for bad in [
            // Scheme, host, and userinfo.
            "https://127.0.0.1:49152/cb",
            "ws://127.0.0.1:49152/cb",
            "http://127.0.0.2:49152/cb",
            "http://evil.test:49152/cb",
            "http://localhost.evil.test:49152/cb",
            "http://user@127.0.0.1:49152/cb",
            "http://user:pass@127.0.0.1:49152/cb",
            "http://@127.0.0.1:49152/cb",
            "http://127.0.0.1:49152@evil.test/cb",
            "http://127.0.0.1.evil.test/cb",
            // Fragments.
            "http://127.0.0.1:49152/cb#fragment",
            "http://127.0.0.1:49152/cb#",
            "http://evil.test#@127.0.0.1/cb",
            // Raw-URI hygiene and lenient parser forms.
            "http://127.0.0.1:49152\\evil/cb",
            "http://127.0.0.1:49152\\@evil.test/cb",
            "http:/127.0.0.1:49152/cb",
            "http:///127.0.0.1:49152/cb",
            "http:127.0.0.1:49152/cb",
            "http://127.1:49152/cb",
            "http://0x7f.0.0.1:49152/cb",
            "http://2130706433:49152/cb",
            "http://%31%32%37.0.0.1:49152/cb",
            "http://127.0.0.1:049152/cb",
            "http://127.0.0.1:080/cb",
            "http://127.0.0.1:/cb",
            "http://127.0.0.1:+80/cb",
            "http://[::1]:049152/cb",
            "http://[::1]:/cb",
            "http://[::1]x/cb",
            "http://[::2]:49152/cb",
            "http://[::ffff:127.0.0.1]:49152/cb",
            "http://0177.0.0.1:49152/cb",
            "http://127.0.0.01:49152/cb",
            "http://127.0.0.1:49152/c b",
            "http://127.0.0.1:49152/cb\t",
            "http://127.0.0.1:49152/caf\u{e9}",
            "//127.0.0.1:49152/cb",
            "/cb",
        ] {
            assert!(!relay.redirect_allowed(bad, ALL), "{bad}");
        }
        assert!(!relay.redirect_allowed("http://localhost:49152/cb", OFF));
        assert!(!relay.redirect_allowed("http://localhost:49152/cb", HTTP_ORIGINS));
        assert!(relay.redirect_allowed("http://localhost:49152/cb", LOCALHOST));
        assert!(relay.redirect_allowed("http://app.localhost:49152/any?x=1", LOCALHOST));
        assert!(!relay.redirect_allowed("http://app.localhost:49152/any", OFF));

        assert!(cors(&relay, "http://127.0.0.1:49152", OFF));
        assert!(cors(&relay, "http://[::1]:3000", OFF));
        assert!(!cors(&relay, "https://127.0.0.1:49152", ALL));
        assert!(!cors(&relay, "http://127.0.0.2:49152", ALL));
        assert!(!cors(&relay, "http://localhost:49152", OFF));
        assert!(cors(&relay, "http://localhost:49152", LOCALHOST));
        assert!(cors(&relay, "http://app.localhost:49152", LOCALHOST));
        assert!(!cors(&relay, "http://app.localhost:49152", OFF));

        // The matcher does not broaden exact loopback or non-loopback matching.
        let exact = relay_with(vec![
            RedirectMatcher::loopback("http://127.0.0.1/cb").unwrap()
        ]);
        assert!(!exact.redirect_allowed("http://127.0.0.1:49152/other", ALL));
    }

    #[test]
    fn loopback_matchers_admit_localhost_subdomains_only_under_the_flag() {
        let relay = relay_with(vec![
            RedirectMatcher::loopback("http://127.0.0.1/oauth/callback").unwrap(),
            RedirectMatcher::loopback_origin("http://[::1]").unwrap(),
        ]);
        for host in [
            "localhost",
            "LOCALHOST",
            "app.localhost",
            "App.LocalHost",
            "a.b.c.localhost",
            "my-app.localhost",
            "1.localhost",
            "xn--bcher-kva.localhost",
        ] {
            let redirect = format!("http://{host}:49152/oauth/callback");
            assert!(relay.redirect_allowed(&redirect, LOCALHOST), "{redirect}");
            assert!(!relay.redirect_allowed(&redirect, OFF), "{redirect}");
            assert!(
                !relay.redirect_allowed(&redirect, HTTP_ORIGINS),
                "{redirect}"
            );
            let origin = format!("http://{host}:49152");
            assert!(cors(&relay, &origin, LOCALHOST), "{origin}");
            assert!(!cors(&relay, &origin, OFF), "{origin}");
        }
        let long_label = format!("{}.localhost", "a".repeat(64));
        let long_name = format!("{}localhost", "a.".repeat(127));
        for host in [
            "localhost.evil.com",
            "evil.localhost.com",
            "localhost.",
            "a..localhost",
            ".localhost",
            "x.localhost.",
            "xlocalhost",
            "x-localhost",
            "-x.localhost",
            "x-.localhost",
            "a_b.localhost",
            "localhost.localhost.evil",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            let redirect = format!("http://{host}:49152/oauth/callback");
            assert!(!relay.redirect_allowed(&redirect, ALL), "{redirect}");
            if let Ok(origin) = Url::parse(&format!("http://{host}:49152")) {
                assert!(!relay.cors_origin_allowed(&origin, ALL), "{host}");
            }
        }
        for bad in [
            "https://app.localhost:49152/oauth/callback",
            "http://app.localhost:49152/oauth/callback#x",
            "http://user@app.localhost:49152/oauth/callback",
            "http://app.localhost%2e:49152/oauth/callback",
            "http:/app.localhost:49152/oauth/callback",
            "http://app.localhost:49152\\@evil.test/oauth/callback",
        ] {
            assert!(!relay.redirect_allowed(bad, ALL), "{bad}");
        }
        // The exact matcher keeps its path and query rules on localhost names.
        assert!(relay.redirect_allowed("http://app.localhost:1/anything?x=1", LOCALHOST));
        let exact = relay_with(vec![RedirectMatcher::loopback(
            "http://127.0.0.1/oauth/callback",
        )
        .unwrap()]);
        assert!(!exact.redirect_allowed("http://app.localhost:1/anything", LOCALHOST));
        assert!(!exact.redirect_allowed("http://app.localhost:1/oauth/callback?x=1", LOCALHOST));
        // Loopback names never satisfy non-loopback matchers.
        let https = relay_with(vec![RedirectMatcher::uri("https://app.example/cb").unwrap()]);
        assert!(!https.redirect_allowed("http://app.localhost:1/cb", ALL));
        assert!(!cors(&https, "http://app.localhost:1", ALL));
    }

    #[test]
    fn http_origins_match_only_under_the_flag() {
        assert!(RedirectMatcher::http_origin("http://dev.example:3000").is_ok());
        assert!(RedirectMatcher::http_origin("http://127.0.0.1:3000").is_ok());
        assert!(RedirectMatcher::http_origin("https://dev.example").is_err());
        assert!(RedirectMatcher::http_origin("http://dev.example/callback").is_err());
        assert!(RedirectMatcher::http_origin("http://user@dev.example").is_err());
        assert!(RedirectMatcher::http_origin("http://dev.example#x").is_err());
        assert!(RedirectMatcher::http_origin("http://dev.example?x").is_err());
        assert!(RedirectMatcher::http_origin("ftp://dev.example").is_err());
        assert!(RedirectMatcher::http_origin("http://dev.example:80").is_ok());
        assert!(RedirectMatcher::http_origin("http://[::1]:3000").is_ok());
        assert!(RedirectMatcher::http_origin("http://[0:0:0:0:0:0:0:1]:3000").is_ok());
        for bad in [
            "http:dev.example:3000",
            "http:/dev.example:3000",
            "http:///dev.example:3000",
            "http://dev.example:080",
            "http://dev.example:03000",
            "http://dev.example:",
            "http://@dev.example:3000",
            "http://%64ev.example:3000",
            "http://127.1:3000",
            "http://dev.example:3000/.",
            "http://dev.example:3000\\",
            " http://dev.example:3000",
            "http://dev.example:3000\t",
        ] {
            assert!(RedirectMatcher::http_origin(bad).is_err(), "{bad}");
        }

        let relay = relay_with(vec![
            RedirectMatcher::http_origin("http://dev.example:3000").unwrap(),
            RedirectMatcher::origin("https://secure.example").unwrap(),
        ]);
        assert!(relay.validate().is_ok());
        assert!(relay.validate_for(HTTP_ORIGINS).is_ok());
        assert!(relay.validate_for(ALL).is_ok());
        for options in [OFF, LOCALHOST] {
            let error = relay.validate_for(options).unwrap_err();
            assert!(error.contains("http://dev.example:3000"), "{error}");
            assert!(error.contains("OAUTHRELAY_ALLOW_HTTP_ORIGINS"), "{error}");
        }
        let https_only = relay_with(vec![
            RedirectMatcher::origin("https://secure.example").unwrap()
        ]);
        assert!(https_only.validate_for(OFF).is_ok());

        for good in [
            "http://dev.example:3000",
            "http://dev.example:3000/",
            "http://dev.example:3000/any/path?x=1",
            "http://DEV.example:3000/cb",
        ] {
            assert!(relay.redirect_allowed(good, HTTP_ORIGINS), "{good}");
            assert!(!relay.redirect_allowed(good, OFF), "{good}");
            assert!(!relay.redirect_allowed(good, LOCALHOST), "{good}");
        }
        for bad in [
            "https://dev.example:3000/cb",
            "http://dev.example/cb",
            "http://dev.example:3001/cb",
            "http://dev.example.evil.test:3000/cb",
            "http://dev.example:3000@evil.test/cb",
            "http://user@dev.example:3000/cb",
            "http://dev.example:3000/cb#fragment",
            "http://dev.example:3000\\@evil.test/cb",
            "http:/dev.example:3000/cb",
            "http:///dev.example:3000/cb",
            "http://dev.example:03000/cb",
            "http://%64ev.example:3000/cb",
            "http://secure.example/cb",
        ] {
            assert!(!relay.redirect_allowed(bad, ALL), "{bad}");
        }
        // An explicit default port is unambiguous, on either side.
        let default_port = relay_with(vec![
            RedirectMatcher::http_origin("http://dev.example").unwrap()
        ]);
        assert!(default_port.redirect_allowed("http://dev.example:80/cb", HTTP_ORIGINS));
        assert!(default_port.redirect_allowed("http://dev.example/cb", HTTP_ORIGINS));
        assert!(!default_port.redirect_allowed("http://dev.example:080/cb", HTTP_ORIGINS));
        let explicit_port = relay_with(vec![
            RedirectMatcher::http_origin("http://dev.example:80").unwrap()
        ]);
        assert!(explicit_port.redirect_allowed("http://dev.example/cb", HTTP_ORIGINS));
        // The https origin keeps matching with or without the flag.
        assert!(relay.redirect_allowed("https://secure.example/cb", OFF));
        assert!(relay.redirect_allowed("https://secure.example/cb", HTTP_ORIGINS));

        assert!(cors(&relay, "http://dev.example:3000", HTTP_ORIGINS));
        assert!(!cors(&relay, "http://dev.example:3000", OFF));
        assert!(!cors(&relay, "http://dev.example:3000", LOCALHOST));
        assert!(!cors(&relay, "https://dev.example:3000", ALL));
        assert!(!cors(&relay, "http://dev.example:3001", ALL));
        assert!(!cors(&relay, "http://secure.example", ALL));
        assert!(cors(&relay, "https://secure.example", OFF));

        // `origin` keeps rejecting http; only `http_origin` builds one.
        assert!(RedirectMatcher::origin("http://dev.example:3000").is_err());
    }
}
