//! Read-only, single-namespace Kubernetes configuration discovery.

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::ListParams,
    core::PartialObjectMeta,
    runtime::{watcher, WatchStreamExt},
    Api, Client, CustomResource, CustomResourceExt, Resource, ResourceExt,
};
use oauthrelay_core::{
    compile_resources, ApiVersion, ClientAuthentication, ConfigProvider, Metadata,
    ProviderSnapshot, RelayResource, RelayResourceSpec, ResourceDocument, SecretResolver,
    SecretSource, SecretString, UpstreamResource, UpstreamResourceSpec,
};
use oauthrelay_secret_resolver::StandardSecretResolver;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

mod schema;

pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub const INITIAL_SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize)]
#[kube(
    group = "oauthrelay.dev",
    version = "v1alpha1",
    kind = "Upstream",
    namespaced
)]
#[serde(transparent)]
pub struct KubernetesUpstreamSpec(pub UpstreamResourceSpec);

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize)]
#[kube(
    group = "oauthrelay.dev",
    version = "v1alpha1",
    kind = "Relay",
    namespaced
)]
#[serde(transparent)]
pub struct KubernetesRelaySpec(pub RelayResourceSpec);

impl JsonSchema for KubernetesUpstreamSpec {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "KubernetesUpstreamSpec".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schema::structural::<UpstreamResourceSpec>()
    }
}
impl JsonSchema for KubernetesRelaySpec {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "KubernetesRelaySpec".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schema::structural::<RelayResourceSpec>()
    }
}

/// Deterministic, installable CRDs generated exclusively from Rust types.
pub fn crds_yaml() -> anyhow::Result<String> {
    Ok(format!(
        "{}---\n{}",
        serde_saphyr::to_string(&Upstream::crd())?,
        serde_saphyr::to_string(&Relay::crd())?
    ))
}

/// Selects exactly one namespace; an explicit override takes precedence.
pub fn select_namespace(explicit: Option<&str>, default: &str) -> anyhow::Result<String> {
    let namespace = explicit.unwrap_or(default);
    if namespace.is_empty()
        || namespace.len() > 63
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !namespace.as_bytes()[0].is_ascii_alphanumeric()
        || !namespace.as_bytes()[namespace.len() - 1].is_ascii_alphanumeric()
    {
        return Err(anyhow!(
            "Kubernetes namespace must be a non-empty DNS label of at most 63 characters"
        ));
    }
    Ok(namespace.to_owned())
}

pub struct KubernetesProvider {
    client: Client,
    namespace: String,
    refresh_interval: Duration,
    aws_secrets: Option<Arc<dyn SecretResolver>>,
}

impl KubernetesProvider {
    pub fn new(
        client: Client,
        namespace: impl Into<String>,
        refresh_interval: Duration,
    ) -> anyhow::Result<Self> {
        let namespace = select_namespace(Some(&namespace.into()), "")?;
        if refresh_interval.is_zero() {
            return Err(anyhow!(
                "Kubernetes refresh interval must be greater than zero"
            ));
        }
        Ok(Self {
            client,
            namespace,
            refresh_interval,
            aws_secrets: None,
        })
    }

    pub fn with_aws_secrets(mut self, resolver: Arc<dyn SecretResolver>) -> Self {
        self.aws_secrets = Some(resolver);
        self
    }

    fn upstreams(&self) -> Api<Upstream> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }
    fn relays(&self) -> Api<Relay> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    async fn compile(
        &self,
        upstreams: impl IntoIterator<Item = Upstream>,
        relays: impl IntoIterator<Item = Relay>,
    ) -> anyhow::Result<ProviderSnapshot> {
        let documents = documents(&self.namespace, upstreams, relays)?;
        let mut resolver = StandardSecretResolver::new(None).with_kubernetes_secrets(Arc::new(
            KubernetesSecrets {
                api: Api::namespaced(self.client.clone(), &self.namespace),
            },
        ));
        if let Some(aws) = &self.aws_secrets {
            resolver = resolver.with_aws_secrets(aws.clone());
        }
        tokio::time::timeout(REQUEST_TIMEOUT, compile_resources(documents, &resolver))
            .await
            .context("Kubernetes configuration compilation timed out")?
    }
}

fn metadata(
    resource: &impl Resource<DynamicType = ()>,
    namespace: &str,
) -> anyhow::Result<Metadata> {
    if resource.namespace().as_deref() != Some(namespace) {
        return Err(anyhow!(
            "resource is outside the Kubernetes provider namespace"
        ));
    }
    let name = resource
        .meta()
        .name
        .clone()
        .ok_or_else(|| anyhow!("Kubernetes resource has no name"))?;
    Ok(Metadata {
        name,
        namespace: Some(namespace.to_owned()),
    })
}

fn documents(
    namespace: &str,
    upstreams: impl IntoIterator<Item = Upstream>,
    relays: impl IntoIterator<Item = Relay>,
) -> anyhow::Result<Vec<ResourceDocument>> {
    let mut result = Vec::new();
    for resource in upstreams {
        result.push(ResourceDocument::Upstream(UpstreamResource {
            metadata: metadata(&resource, namespace)?,
            api_version: ApiVersion::V1Alpha1,
            spec: resource.spec.0,
        }));
    }
    for resource in relays {
        result.push(ResourceDocument::Relay(RelayResource {
            metadata: metadata(&resource, namespace)?,
            api_version: ApiVersion::V1Alpha1,
            spec: resource.spec.0,
        }));
    }
    Ok(result)
}

struct KubernetesSecrets {
    api: Api<Secret>,
}

#[async_trait]
impl SecretResolver for KubernetesSecrets {
    async fn resolve_value(&self, _: &str) -> anyhow::Result<SecretString> {
        Err(anyhow!(
            "inline values are resolved by the standard resolver"
        ))
    }

    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
        let SecretSource::SecretKeyRef { name, key } = source else {
            return Err(anyhow!("source is not a Kubernetes Secret reference"));
        };
        // Names enter an API path; never allow a reference to escape that path.
        if name.is_empty()
            || name.len() > 253
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
            || name.split('.').any(|label| {
                label.is_empty()
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            })
            || key.is_empty()
        {
            return Err(anyhow!(
                "secretKeyRef requires a valid Secret name and non-empty key"
            ));
        }
        let secret = self
            .api
            .get(name)
            .await
            .context("read referenced Kubernetes Secret")?;
        let bytes = secret
            .data
            .as_ref()
            .and_then(|data| data.get(key))
            .ok_or_else(|| anyhow!("referenced Kubernetes Secret key does not exist"))?;
        let value =
            String::from_utf8(bytes.0.clone()).context("Kubernetes Secret value must be UTF-8")?;
        Ok(SecretString::new(value))
    }
}

async fn list<K>(api: Api<K>) -> anyhow::Result<Vec<K>>
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug,
{
    let mut result = Vec::new();
    let mut params = ListParams::default().limit(500);
    loop {
        let page = api.list(&params).await?;
        result.extend(page.items);
        match page.metadata.continue_.filter(|token| !token.is_empty()) {
            Some(token) => params = params.continue_token(&token),
            None => return Ok(result),
        }
    }
}

/// A relist becomes visible only after InitDone, including removal of absent objects.
struct Store<K> {
    objects: BTreeMap<String, K>,
    staging: Option<BTreeMap<String, K>>,
    initialized: bool,
}

impl<K> Default for Store<K> {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            staging: None,
            initialized: false,
        }
    }
}

impl<K: Resource> Store<K> {
    fn ready(&self) -> bool {
        self.initialized && self.staging.is_none()
    }

    fn apply(&mut self, event: watcher::Event<K>) -> bool {
        use watcher::Event::*;
        match event {
            Init => {
                self.staging = Some(BTreeMap::new());
                false
            }
            InitApply(object) => {
                self.staging
                    .get_or_insert_with(BTreeMap::new)
                    .insert(object.name_any(), object);
                false
            }
            InitDone => {
                self.objects = self.staging.take().unwrap_or_default();
                self.initialized = true;
                true
            }
            Apply(object) => {
                self.objects.insert(object.name_any(), object);
                true
            }
            Delete(object) => {
                self.objects.remove(&object.name_any());
                true
            }
        }
    }
}

fn referenced_secrets(upstreams: &Store<Upstream>, relays: &Store<Relay>) -> HashSet<String> {
    upstreams
        .objects
        .values()
        .map(|u| &u.spec.0.oauth_client.client_secret)
        .chain(
            relays
                .objects
                .values()
                .filter_map(|r| match &r.spec.0.client_authentication {
                    ClientAuthentication::ClientSecret { client_secret, .. } => Some(client_secret),
                    _ => None,
                }),
        )
        .filter_map(|secret| match secret.value_from() {
            Some(SecretSource::SecretKeyRef { name, .. }) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn watch_event<K: Resource>(
    store: &mut Store<K>,
    event: Option<watcher::Result<watcher::Event<K>>>,
    kind: &str,
) -> anyhow::Result<bool> {
    match event {
        Some(Ok(event)) => Ok(store.apply(event)),
        Some(Err(_)) => {
            // Deserialization errors may contain secret-bearing field values.
            tracing::warn!(kind, "Kubernetes watch failed; reconnecting with backoff");
            Ok(false)
        }
        None => Err(anyhow!("Kubernetes {kind} watch stopped")),
    }
}

#[async_trait]
impl ConfigProvider for KubernetesProvider {
    fn name(&self) -> &str {
        "kubernetes"
    }

    async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        tokio::time::timeout(INITIAL_SYNC_TIMEOUT, async {
            let (upstreams, relays) =
                tokio::try_join!(list(self.upstreams()), list(self.relays()))?;
            self.compile(upstreams, relays).await
        })
        .await
        .context("initial Kubernetes configuration read timed out")?
    }

    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
        let mut upstream_watch = watcher(self.upstreams(), watcher::Config::default())
            .default_backoff()
            .boxed();
        let mut relay_watch = watcher(self.relays(), watcher::Config::default())
            .default_backoff()
            .boxed();
        let secret_api: Api<PartialObjectMeta<Secret>> =
            Api::namespaced(self.client.clone(), &self.namespace);
        let mut secret_watch = watcher(secret_api, watcher::Config::default())
            .default_backoff()
            .boxed();
        let mut upstreams = Store::default();
        let mut relays = Store::default();
        let mut secrets = Store::default();
        let deadline = tokio::time::sleep(INITIAL_SYNC_TIMEOUT);
        tokio::pin!(deadline);
        let mut refresh = tokio::time::interval(self.refresh_interval);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        refresh.tick().await;
        let mut published = false;
        loop {
            let changed = tokio::select! {
                _ = tx.closed() => return Ok(()),
                _ = &mut deadline, if !published => return Err(anyhow!("initial Kubernetes synchronization timed out")),
                event = upstream_watch.next() => watch_event(&mut upstreams, event, "Upstream")?,
                event = relay_watch.next() => watch_event(&mut relays, event, "Relay")?,
                event = secret_watch.next() => {
                    let relevant = match &event {
                        Some(Ok(watcher::Event::Apply(object) | watcher::Event::Delete(object))) =>
                            referenced_secrets(&upstreams, &relays).contains(&object.name_any()),
                        _ => true,
                    };
                    watch_event(&mut secrets, event, "Secret")? && relevant
                }
                _ = refresh.tick() => true,
            };
            if changed && upstreams.ready() && relays.ready() && secrets.ready() {
                let compiled = self.compile(
                    upstreams.objects.values().cloned(),
                    relays.objects.values().cloned(),
                );
                let result = tokio::select! {
                    _ = tx.closed() => return Ok(()),
                    _ = &mut deadline, if !published => return Err(anyhow!("initial Kubernetes synchronization timed out")),
                    result = compiled => result,
                };
                match result {
                    Ok(snapshot) => {
                        if tx.send(snapshot).is_err() {
                            return Ok(());
                        }
                        published = true;
                    }
                    Err(error) if !published => {
                        return Err(error.context("invalid initial Kubernetes configuration"))
                    }
                    Err(error) => {
                        tracing::error!(namespace = %self.namespace, %error, "invalid Kubernetes configuration; keeping last good snapshot")
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
