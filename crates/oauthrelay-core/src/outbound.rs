//! A hook for vetting the URLs the relay requests, and the one place that sends them.

use crate::ResourceKey;
use async_trait::async_trait;
use std::{fmt, sync::Arc};
use url::Url;

/// Decides whether the relay may send an HTTP request.
///
/// The URLs come from the configuration, and also from documents that upstreams and relying
/// parties serve: an issuer's discovery document names its own `jwks_uri`, which the relay then
/// fetches and serves. An embedder whose issuers are not all trusted should therefore vet them.
///
/// [`check`](Self::check) runs before every request the relay sends with `RelayConfig::http` or
/// `RelayConfig::client_assertion_http`, for the URL the request is made to. The relay sends the
/// request itself afterwards, through the same client, and does not accept a response that
/// answers from another URL or with a redirect, so a policy-approved URL cannot lead elsewhere.
///
/// A denied request is never sent and counts as unavailable, never as a definite absence: relay
/// discovery and `/jwks` answer 502, a code redemption that needs the JWKS answers 502
/// `server_error` and leaves the code unconsumed, token and refresh requests answer 502, and a
/// client assertion is rejected as `invalid_client`. The relay does not remember denials, so
/// every request that needs a denied URL calls the policy again.
///
/// # What a policy can and cannot do
///
/// The policy sees the URL, not the connection. Use it for scheme, host and port allow-lists, and
/// check IP-literal hosts yourself (`Url::host()` gives `Host::Ipv4` or `Host::Ipv6`), because a
/// custom DNS resolver is never consulted for them. Do not resolve host names inside the policy:
/// the HTTP client resolves the name again when it connects, so a name can answer differently the
/// second time (DNS rebinding). Enforce address ranges for host names where the connection is
/// made instead: install a `reqwest::dns::Resolve` that filters addresses with
/// `ClientBuilder::dns_resolver` on both clients. An `HTTP_PROXY` or `HTTPS_PROXY` makes the proxy
/// resolve names, which skips that resolver, so use `ClientBuilder::no_proxy` on both clients or
/// accept the limit knowingly.
///
/// # Caching
///
/// Metadata and keys are cached per purpose and URL (discovery for 60 minutes, JWKS for 10), and
/// the policy is not asked again when a cached answer is served. A policy that becomes stricter
/// takes effect for cached entries only when they expire.
#[async_trait]
pub trait OutboundPolicy: Send + Sync + 'static {
    /// Returns `Err` to deny the request.
    async fn check(&self, request: &OutboundRequest<'_>) -> Result<(), OutboundDenied>;
}

/// An outbound request, as offered to an [`OutboundPolicy`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct OutboundRequest<'a> {
    /// The URL the request is sent to.
    pub url: &'a Url,
    pub purpose: OutboundPurpose,
    /// The relay the request is made for, when there is one. Metadata and keys are cached per
    /// upstream, so a cached answer is shared by the relays of an upstream.
    pub relay: Option<&'a ResourceKey>,
    /// The upstream the request is made for, when there is one. Client-assertion fetches are made
    /// on behalf of a relay's client and have none.
    pub upstream: Option<&'a ResourceKey>,
}

/// What an outbound request is for.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum OutboundPurpose {
    /// An upstream's OpenID discovery document.
    Discovery,
    /// An upstream's JWKS, used to verify its ID tokens and served at the relay's `/jwks`.
    Jwks,
    /// The upstream token endpoint, for the authorization-code exchange.
    TokenExchange,
    /// The upstream token endpoint, for a refresh grant.
    Refresh,
    /// The discovery document of a `private_key_jwt` client's issuer.
    ClientAssertionMetadata,
    /// The JWKS verifying a `private_key_jwt` client's assertions.
    ClientAssertionJwks,
}

impl OutboundPurpose {
    /// A stable lowercase name, as used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Jwks => "jwks",
            Self::TokenExchange => "token_exchange",
            Self::Refresh => "refresh",
            Self::ClientAssertionMetadata => "client_assertion_metadata",
            Self::ClientAssertionJwks => "client_assertion_jwks",
        }
    }
}

impl fmt::Display for OutboundPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An [`OutboundPolicy`] denial.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct OutboundDenied {
    message: String,
}

impl OutboundDenied {
    /// The message is written to the relay's logs and never sent to a client. It must not contain
    /// URL paths, query strings, or secrets: say why the request was denied, not what it was.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The relay and upstream an outbound request is made for.
#[derive(Clone, Copy, Default)]
pub(crate) struct Scope<'a> {
    pub relay: Option<&'a ResourceKey>,
    pub upstream: Option<&'a ResourceKey>,
}

/// Why a request produced no usable response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendError {
    /// The policy denied it; nothing was sent.
    Denied,
    /// It failed in transport, or the answer came from another URL or was a redirect.
    Failed,
}

/// Sends `request` after the policy has approved its URL. This is the only place the relay
/// sends a request: the URL that is checked is the URL that is sent, and the response must come
/// from it and must not be a redirect. Denials are logged with the purpose and host, never the
/// path or query, which can carry secrets.
pub(crate) async fn send_checked(
    client: &reqwest::Client,
    policy: Option<&Arc<dyn OutboundPolicy>>,
    request: reqwest::Request,
    purpose: OutboundPurpose,
    scope: Scope<'_>,
) -> Result<reqwest::Response, SendError> {
    let url = request.url().clone();
    let host = url.host_str().unwrap_or("-");
    if let Some(policy) = policy {
        let offered = OutboundRequest {
            url: &url,
            purpose,
            relay: scope.relay,
            upstream: scope.upstream,
        };
        if let Err(denied) = policy.check(&offered).await {
            tracing::warn!(
                target: "oauthrelay::outbound",
                %purpose,
                host,
                reason = denied.message(),
                "outbound request denied by policy"
            );
            return Err(SendError::Denied);
        }
    }
    #[allow(clippy::disallowed_methods)]
    let response = client
        .execute(request)
        .await
        .map_err(|_| SendError::Failed)?;
    if response.url() != &url || response.status().is_redirection() {
        tracing::warn!(
            target: "oauthrelay::outbound",
            %purpose,
            host,
            status = response.status().as_u16(),
            "outbound response rejected: redirected, or answered from another URL"
        );
        return Err(SendError::Failed);
    }
    Ok(response)
}
