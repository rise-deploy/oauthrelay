//! A hook for vetting the URLs the relay requests.

use async_trait::async_trait;
use std::{fmt, sync::Arc};
use url::Url;

/// Decides whether the relay may send an HTTP request to a URL.
///
/// The URLs come from the configuration, and also from documents that upstreams and relying
/// parties serve: an issuer's discovery document names its own `jwks_uri`, which the relay then
/// fetches and serves. An embedder whose issuers are not all trusted should therefore reject
/// URLs that point into its own network (loopback, link-local and metadata addresses, private
/// ranges), including after DNS resolution.
///
/// [`check`](Self::check) runs before every request the relay sends with `RelayConfig::http` or
/// `RelayConfig::client_assertion_http`, with the URL as the relay holds it.
/// It does not run again for responses served from the relay's metadata and key caches. A denied
/// request is never sent and counts as unavailable, never as a definite absence: relay discovery
/// and `/jwks` answer 502, a code redemption that needs the JWKS answers 502 `server_error` and
/// leaves the code unconsumed, token and refresh requests answer 502, and a client assertion is
/// rejected as `invalid_client`.
///
/// # Redirects
///
/// The policy sees only the initial URL. A client that follows redirects can be sent to a URL the
/// policy never saw, so the clients in `RelayConfig` must not follow redirects (as
/// `default_client_builder` arranges), or must enforce the policy
/// themselves on every hop.
#[async_trait]
pub trait OutboundPolicy: Send + Sync + 'static {
    /// Returns `Err` to deny the request.
    async fn check(&self, url: &Url, purpose: OutboundPurpose) -> Result<(), OutboundDenied>;
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

/// An [`OutboundPolicy`] denial. The message is for logs and is never sent to a client.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct OutboundDenied {
    message: String,
}

impl OutboundDenied {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Whether the request may be sent. A denial is logged with the purpose and the host, never the
/// path or query, which can carry secrets.
pub(crate) async fn permit(
    policy: Option<&Arc<dyn OutboundPolicy>>,
    url: &Url,
    purpose: OutboundPurpose,
) -> bool {
    let Some(policy) = policy else {
        return true;
    };
    match policy.check(url, purpose).await {
        Ok(()) => true,
        Err(denied) => {
            tracing::warn!(
                target: "oauthrelay::outbound",
                %purpose,
                host = url.host_str().unwrap_or("-"),
                reason = denied.message(),
                "outbound request denied by policy"
            );
            false
        }
    }
}
