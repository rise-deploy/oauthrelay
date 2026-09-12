use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::Ipv4Addr,
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
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
        {
            return Err("must contain non-empty URL-safe path segments".into());
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
}

#[derive(Clone, Debug, Deserialize)]
pub struct Relay {
    pub key: ResourceKey,
    pub upstream: ResourceKey,
    pub client_auth: ClientAuth,
    pub scopes: Vec<String>,
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub required_id_token_claims: HashMap<String, String>,
    pub redirect_policy: Vec<RedirectMatcher>,
}

#[derive(Clone, Debug, Deserialize)]
pub enum RedirectMatcher {
    Uri(String),
    Origin(Origin),
    Loopback(String),
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

    pub fn loopback(value: &str) -> Result<Self, String> {
        validate_loopback_uri(value)?;
        Ok(Self::Loopback(value.to_owned()))
    }

    fn identity(&self) -> String {
        match self {
            Self::Uri(value) => format!("uri\0{value}"),
            Self::Origin(value) => format!("origin\0{}", value.url()),
            Self::Loopback(value) => format!("loopback\0{value}"),
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
    pub fn redirect_allowed(&self, redirect: &str, allow_localhost_loopback: bool) -> bool {
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
                origin.url().scheme() == "https" && origin.matches(&url)
            }
            RedirectMatcher::Loopback(value) => Url::parse(value).is_ok_and(|base| {
                validate_loopback_uri(value).is_ok()
                    && url.scheme() == "http"
                    && loopback_host_matches(&base, &url, allow_localhost_loopback)
                    && raw_path_and_query(value)
                        .is_some_and(|tail| raw_path_and_query(redirect) == Some(tail))
            }),
        })
    }

    pub fn cors_origin_allowed(&self, origin: &Url, allow_localhost_loopback: bool) -> bool {
        if !valid_origin_url(origin) {
            return false;
        }
        self.redirect_policy.iter().any(|matcher| match matcher {
            RedirectMatcher::Uri(value) => {
                validate_exact_uri(value).is_ok()
                    && Url::parse(value).is_ok_and(|redirect| same_origin(&redirect, origin))
            }
            RedirectMatcher::Origin(allowed) => {
                allowed.url().scheme() == "https" && allowed.matches(origin)
            }
            RedirectMatcher::Loopback(value) => Url::parse(value).is_ok_and(|base| {
                validate_loopback_uri(value).is_ok()
                    && origin.scheme() == "http"
                    && loopback_host_matches(&base, origin, allow_localhost_loopback)
            }),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self
            .required_id_token_claims
            .keys()
            .any(|claim| claim.is_empty())
        {
            return Err("required_id_token_claims must not contain an empty claim name".into());
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
                RedirectMatcher::Origin(value) if value.url().scheme() != "https" => {
                    return Err("redirect_policy origin must use https".into())
                }
                RedirectMatcher::Origin(_) => {}
                RedirectMatcher::Loopback(value) => validate_loopback_uri(value)?,
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
            && matches!(candidate.host(), Some(Host::Domain(domain)) if domain.eq_ignore_ascii_case("localhost")))
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

    #[test]
    fn redirect_matchers_are_explicit_and_distinct() {
        let relay = Relay {
            key: ResourceKey::new("google").unwrap(),
            upstream: ResourceKey::new("google").unwrap(),
            client_auth: ClientAuth::Public,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            redirect_policy: vec![
                RedirectMatcher::uri("https://exact.example/cb?channel=stable&next=%2Fhome")
                    .unwrap(),
                RedirectMatcher::origin("https://preview.example.com").unwrap(),
                RedirectMatcher::loopback("http://127.0.0.1/oauth/callback?source=cli").unwrap(),
                RedirectMatcher::loopback("http://[::1]/oauth/callback").unwrap(),
            ],
        };
        assert!(relay.redirect_allowed(
            "https://exact.example/cb?channel=stable&next=%2Fhome",
            false
        ));
        assert!(!relay.redirect_allowed(
            "https://exact.example/cb?next=%2Fhome&channel=stable",
            false
        ));
        assert!(!relay.redirect_allowed(
            "https://exact.example/cb?channel=stable&next=%2fhome",
            false
        ));
        assert!(relay.redirect_allowed("https://preview.example.com/any/path?x=1", false));
        assert!(!relay.redirect_allowed("https://preview.example.com:8443/any/path", false));
        assert!(relay.redirect_allowed("http://127.0.0.1:49152/oauth/callback?source=cli", false));
        assert!(relay.redirect_allowed("http://[::1]:49152/oauth/callback", false));
        assert!(!relay.redirect_allowed("http://localhost:49152/oauth/callback?source=cli", false));
        assert!(relay.redirect_allowed("http://localhost:49152/oauth/callback?source=cli", true));
        let normalized_path = Relay {
            redirect_policy: vec![
                RedirectMatcher::loopback("http://127.0.0.1/a/../callback").unwrap()
            ],
            ..relay.clone()
        };
        assert!(!normalized_path.redirect_allowed("http://127.0.0.1:49152/callback", false));
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
            assert!(!relay.redirect_allowed(bad, true), "{bad}");
        }
        assert!(relay.validate().is_ok());
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
            client_auth: ClientAuth::Public,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            redirect_policy: vec![
                RedirectMatcher::uri("https://exact.example/cb").unwrap(),
                RedirectMatcher::origin("https://preview.example").unwrap(),
                RedirectMatcher::loopback("http://127.0.0.1/callback").unwrap(),
            ],
        };
        assert!(relay.cors_origin_allowed(&Url::parse("https://exact.example").unwrap(), false));
        assert!(!relay.redirect_allowed("https://exact.example/other", false));
        assert!(relay.cors_origin_allowed(&Url::parse("https://preview.example").unwrap(), false));
        assert!(relay.cors_origin_allowed(&Url::parse("http://127.0.0.1:49152").unwrap(), false));
        assert!(!relay.cors_origin_allowed(&Url::parse("http://localhost:49152").unwrap(), false));
        assert!(relay.cors_origin_allowed(&Url::parse("http://localhost:49152").unwrap(), true));
    }
}
