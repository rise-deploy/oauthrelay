use crate::{Relay, RelayMap, ResourceKey, Upstream, UpstreamMap};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::{watch, Mutex};

#[derive(Debug, Error)]
#[error("resource resolution failed: {0}")]
pub struct ResolveError(pub String);

#[derive(Debug, Error)]
#[error("replay cache failed: {0}")]
pub struct CacheError(pub String);

#[async_trait]
pub trait ResourceResolver: Send + Sync + 'static {
    async fn resolve_relay(&self, key: &ResourceKey) -> Result<Option<Arc<Relay>>, ResolveError>;
    async fn resolve_upstream(
        &self,
        key: &ResourceKey,
    ) -> Result<Option<Arc<Upstream>>, ResolveError>;
}

#[derive(Clone, Debug, Default)]
pub struct ProviderSnapshot {
    pub upstreams: UpstreamMap,
    pub relays: RelayMap,
}

impl ProviderSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        for (key, upstream) in &self.upstreams {
            upstream
                .validate()
                .map_err(|error| format!("Upstream/{key}: {error}"))?;
        }
        for (key, relay) in &self.relays {
            relay
                .validate()
                .map_err(|error| format!("Relay/{key}: {error}"))?;
            if !self.upstreams.contains_key(&relay.upstream) {
                return Err(format!(
                    "Relay/{key}: upstreamRef {} does not exist",
                    relay.upstream
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
pub trait ConfigProvider: Send + Sync + 'static {
    fn name(&self) -> &str;
    /// Produces one complete snapshot for startup or invocation-driven refresh.
    async fn load(&self) -> anyhow::Result<ProviderSnapshot>;
    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()>;
}

#[async_trait]
pub trait ReplayCache: Send + Sync + 'static {
    /// Atomically record an absent ID for the full TTL; return false if already present.
    /// Share durable storage across serving instances when enforcing deployment-wide single use.
    async fn first_use(&self, id: &str, ttl: Duration) -> Result<bool, CacheError>;
}

#[derive(Default)]
pub struct MemoryReplayCache {
    entries: Mutex<HashMap<String, std::time::Instant>>,
}

#[async_trait]
impl ReplayCache for MemoryReplayCache {
    async fn first_use(&self, id: &str, ttl: Duration) -> Result<bool, CacheError> {
        let now = std::time::Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_, expires| *expires > now);
        if entries.contains_key(id) {
            return Ok(false);
        }
        entries.insert(id.to_owned(), now + ttl);
        Ok(true)
    }
}

pub struct Registry {
    resources: ArcSwap<ProviderSnapshot>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            resources: ArcSwap::from_pointee(ProviderSnapshot::default()),
        }
    }
}

impl Registry {
    pub fn replace(&self, resources: ProviderSnapshot) {
        self.resources.store(Arc::new(resources));
    }

    pub fn snapshot(&self) -> Arc<ProviderSnapshot> {
        self.resources.load_full()
    }

    pub fn merge_ordered<'a>(
        snapshots: impl IntoIterator<Item = (&'a str, &'a ProviderSnapshot)>,
    ) -> ProviderSnapshot {
        let mut merged = ProviderSnapshot::default();
        for (provider, snapshot) in snapshots {
            for (key, value) in &snapshot.upstreams {
                if merged.upstreams.contains_key(key) {
                    tracing::error!(%provider, %key, "provider Upstream key collision; keeping earlier provider");
                } else {
                    merged.upstreams.insert(key.clone(), value.clone());
                }
            }
            for (key, value) in &snapshot.relays {
                if merged.relays.contains_key(key) {
                    tracing::error!(%provider, %key, "provider Relay key collision; keeping earlier provider");
                } else {
                    merged.relays.insert(key.clone(), value.clone());
                }
            }
        }
        merged
    }
}

#[async_trait]
impl ResourceResolver for Registry {
    async fn resolve_relay(&self, key: &ResourceKey) -> Result<Option<Arc<Relay>>, ResolveError> {
        Ok(self.resources.load().relays.get(key).cloned())
    }

    async fn resolve_upstream(
        &self,
        key: &ResourceKey,
    ) -> Result<Option<Arc<Upstream>>, ResolveError> {
        Ok(self.resources.load().upstreams.get(key).cloned())
    }
}

#[async_trait]
impl ResourceResolver for ProviderSnapshot {
    async fn resolve_relay(&self, key: &ResourceKey) -> Result<Option<Arc<Relay>>, ResolveError> {
        Ok(self.relays.get(key).cloned())
    }

    async fn resolve_upstream(
        &self,
        key: &ResourceKey,
    ) -> Result<Option<Arc<Upstream>>, ResolveError> {
        Ok(self.upstreams.get(key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientAuth, RedirectMatcher, SecretString};
    use url::Url;

    fn upstream(key: &str) -> Arc<Upstream> {
        Arc::new(Upstream {
            key: ResourceKey::new(key).unwrap(),
            issuer_url: Url::parse("https://issuer.example").unwrap(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            client_id: "id".into(),
            client_secret: SecretString::new("secret"),
        })
    }

    fn relay(key: &str, upstream: &str) -> Arc<Relay> {
        Arc::new(Relay {
            key: ResourceKey::new(key).unwrap(),
            upstream: ResourceKey::new(upstream).unwrap(),
            client_auth: ClientAuth::Public,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: HashMap::new(),
            redirect_policy: vec![RedirectMatcher::uri("https://app.example/callback").unwrap()],
        })
    }

    #[test]
    fn validates_references() {
        let mut snapshot = ProviderSnapshot::default();
        snapshot
            .relays
            .insert("relay".parse().unwrap(), relay("relay", "missing"));
        assert!(snapshot.validate().unwrap_err().contains("does not exist"));
        snapshot
            .upstreams
            .insert("missing".parse().unwrap(), upstream("missing"));
        snapshot.validate().unwrap();
    }

    #[test]
    fn earlier_provider_wins_each_resource_kind() {
        let key = ResourceKey::new("same").unwrap();
        let first_upstream = upstream("same");
        let first_relay = relay("same", "same");
        let mut first = ProviderSnapshot::default();
        first.upstreams.insert(key.clone(), first_upstream.clone());
        first.relays.insert(key.clone(), first_relay.clone());
        let mut second = ProviderSnapshot::default();
        second.upstreams.insert(key.clone(), upstream("same"));
        second.relays.insert(key.clone(), relay("same", "same"));
        let merged = Registry::merge_ordered([("first", &first), ("second", &second)]);
        assert!(Arc::ptr_eq(
            merged.upstreams.get(&key).unwrap(),
            &first_upstream
        ));
        assert!(Arc::ptr_eq(merged.relays.get(&key).unwrap(), &first_relay));
    }
}
