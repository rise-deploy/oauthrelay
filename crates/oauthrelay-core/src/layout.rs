//! URL layout of the relay router: which paths below `public_url` serve which endpoint.

use crate::ResourceKey;
use std::sync::Arc;

/// An endpoint served by the relay router.
///
/// Every endpoint is keyed by the *relay* key except [`Endpoint::Callback`], which is keyed by the
/// *upstream* key: one upstream callback is shared by every relay that uses the upstream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Endpoint {
    /// Relay authorization endpoint (relay key).
    Authorize,
    /// Upstream redirect URI that receives the provider's response (upstream key).
    Callback,
    /// Relay token endpoint (relay key).
    Token,
    /// Relay OpenID Connect discovery document (relay key).
    Discovery,
    /// Relay JWKS endpoint (relay key).
    Jwks,
}

impl Endpoint {
    /// Every endpoint, for layouts and tests that enumerate them.
    pub const ALL: [Endpoint; 5] = [
        Endpoint::Authorize,
        Endpoint::Callback,
        Endpoint::Token,
        Endpoint::Discovery,
        Endpoint::Jwks,
    ];
}

/// Maps request paths to endpoints and back.
///
/// The router serves everything below [`RelayConfig::public_url`](crate::RelayConfig::public_url)
/// and asks the layout to interpret the remainder. The same layout renders every URL the router
/// hands out: the upstream `redirect_uri`, the `authorization_endpoint` and `token_endpoint` in the
/// discovery document, and the default `private_key_jwt` audience. `path` must therefore invert
/// `parse`: `parse(&path(endpoint, key))` returns `(endpoint, key)`.
///
/// A callback shares the key space of its upstream. A layout may serve it under the same key as the
/// relay, but that only lines up when the relay key equals its upstream key; otherwise the callback
/// lands under the upstream's key.
pub trait PathLayout: Send + Sync + 'static {
    /// Interprets a request path below `public_url`. The path is the raw request path with the
    /// `public_url` path and exactly one following `/` removed: percent-escapes are not decoded
    /// (so `%2F` and `%2E%2E` arrive verbatim), and trailing, repeated and empty segments are
    /// passed through as-is. The layout accepts or rejects them. Returns `None` for paths the
    /// layout does not serve, which the router answers with `404`.
    fn parse(&self, path: &str) -> Option<(Endpoint, ResourceKey)>;

    /// The path below `public_url`, without a leading slash, at which `endpoint` is served for
    /// `key`, already percent-encoded where its characters require it. For [`Endpoint::Callback`] the key is the upstream key; for the others, the relay key.
    fn path(&self, endpoint: Endpoint, key: &ResourceKey) -> String;
}

/// How [`DefaultLayout`] turns the path segments between the namespace and the endpoint into a
/// [`ResourceKey`].
#[derive(Clone)]
pub enum KeyStrategy {
    /// One segment: `/relay/{key}/…`.
    SingleSegment,
    /// Two segments joined by `/`: `/relay/{project}/{extension}/…` yields the key
    /// `{project}/{extension}`.
    TwoSegment,
    /// A host-supplied mapper from the key segments to a key, `None` to reject the path.
    Custom(Arc<KeyMapper>),
}

/// Maps the key segments of a [`DefaultLayout`] path to a [`ResourceKey`].
///
/// A mapper only goes from segments to keys, so [`DefaultLayout::path`](PathLayout::path) renders
/// every key verbatim, one segment per `/`-separated part. A mapper that does not accept a key's
/// parts as given produces URLs the router itself would not recognise.
pub type KeyMapper = dyn Fn(&[&str]) -> Option<ResourceKey> + Send + Sync;

/// The built-in layout:
///
/// | Endpoint | Path |
/// |---|---|
/// | authorize | `relay/{key}/authorize` |
/// | token | `relay/{key}/token` |
/// | jwks | `relay/{key}/jwks` |
/// | discovery | `relay/{key}/.well-known/openid-configuration` |
/// | callback | `upstream/{key}/callback` |
///
/// `{key}` is rendered and parsed according to the [`KeyStrategy`].
#[derive(Clone)]
pub struct DefaultLayout {
    keys: KeyStrategy,
}

impl DefaultLayout {
    /// The built-in layout, with relay and upstream keys parsed according to `keys`.
    pub fn new(keys: KeyStrategy) -> Self {
        Self { keys }
    }
}

impl PathLayout for DefaultLayout {
    fn parse(&self, path: &str) -> Option<(Endpoint, ResourceKey)> {
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
        let key = match &self.keys {
            KeyStrategy::SingleSegment if key_parts.len() == 1 => {
                ResourceKey::new(key_parts[0]).ok()
            }
            KeyStrategy::TwoSegment if key_parts.len() == 2 => {
                ResourceKey::new(format!("{}/{}", key_parts[0], key_parts[1])).ok()
            }
            KeyStrategy::Custom(map) => map(key_parts),
            _ => None,
        }?;
        Some((endpoint, key))
    }

    fn path(&self, endpoint: Endpoint, key: &ResourceKey) -> String {
        match endpoint {
            Endpoint::Authorize => format!("relay/{key}/authorize"),
            Endpoint::Callback => format!("upstream/{key}/callback"),
            Endpoint::Token => format!("relay/{key}/token"),
            Endpoint::Discovery => format!("relay/{key}/.well-known/openid-configuration"),
            Endpoint::Jwks => format!("relay/{key}/jwks"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> ResourceKey {
        ResourceKey::new(value).unwrap()
    }

    #[test]
    fn default_layout_renders_the_documented_paths() {
        let layout = DefaultLayout::new(KeyStrategy::TwoSegment);
        let key = key("project/ext");
        let paths: Vec<_> = Endpoint::ALL
            .iter()
            .map(|endpoint| layout.path(*endpoint, &key))
            .collect();
        assert_eq!(
            paths,
            [
                "relay/project/ext/authorize",
                "upstream/project/ext/callback",
                "relay/project/ext/token",
                "relay/project/ext/.well-known/openid-configuration",
                "relay/project/ext/jwks",
            ]
        );
    }

    #[test]
    fn default_layout_round_trips_for_both_key_strategies() {
        for (strategy, key) in [
            (KeyStrategy::SingleSegment, key("google")),
            (KeyStrategy::TwoSegment, key("project/ext")),
        ] {
            let layout = DefaultLayout::new(strategy);
            for endpoint in Endpoint::ALL {
                let path = layout.path(endpoint, &key);
                assert_eq!(layout.parse(&path), Some((endpoint, key.clone())), "{path}");
            }
        }
    }

    #[test]
    fn default_layout_round_trips_a_custom_mapper_that_accepts_the_rendered_key() {
        let layout = DefaultLayout::new(KeyStrategy::Custom(Arc::new(|parts: &[&str]| {
            ResourceKey::new(parts.join("/")).ok()
        })));
        let key = key("a/b/c");
        for endpoint in Endpoint::ALL {
            let path = layout.path(endpoint, &key);
            assert_eq!(layout.parse(&path), Some((endpoint, key.clone())), "{path}");
        }
    }

    #[test]
    fn default_layout_rejects_paths_outside_its_layout() {
        let single = DefaultLayout::new(KeyStrategy::SingleSegment);
        assert!(single.parse("relay/google/token").is_some());
        assert!(single.parse("relay/project/ext/token").is_none());
        assert!(single.parse("upstream/google/callback").is_some());
        assert!(single.parse("relay/google/callback").is_none());
        assert!(single.parse("upstream/google/token").is_none());
        assert!(single.parse("relay//token").is_none());
        assert!(single.parse("").is_none());
        assert!(single.parse("relay/a%2Fb/token").is_none());
        assert!(single.parse("relay/%2E%2E/token").is_none());
        let two = DefaultLayout::new(KeyStrategy::TwoSegment);
        assert!(two
            .parse("relay/project/ext/.well-known/openid-configuration")
            .is_some());
        assert!(two.parse("relay/google/token").is_none());
    }
}
