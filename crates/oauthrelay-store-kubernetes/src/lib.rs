//! Kubernetes backend for oauthrelay's [`TransientStore`].
//!
//! Every record is one namespaced custom resource. The default mapping is oauthrelay's own
//! `TransientRecord` (`transientrecords.oauthrelay.dev`, installed from `oauthrelay crds`):
//!
//! | Field | Meaning |
//! | --- | --- |
//! | `metadata.name` | [`object_name`]: `oauthrelay-` plus the lowercase base32 of the key's SHA-256. |
//! | `metadata.labels` | `app.kubernetes.io/managed-by: oauthrelay`, and `oauthrelay.dev/purpose` with the key's first segment (`replay`, `refresh`). |
//! | `spec.key` | The store key, for inspection. It holds hashes and random IDs, never a secret. |
//! | `spec.value` | The opaque value, base64. |
//! | `spec.expiresAt` | Expiry as RFC 3339 with millisecond precision. |
//!
//! The same records can live in Dex's `AuthCode` resource (`authcodes.dex.coreos.com`) instead; see
//! [`RecordMapping::DexAuthCode`]. Everything below the field layout is identical.
//!
//! The runtime role needs `get`, `list`, `create`, `update` and `delete` on the resource in one
//! namespace.
//!
//! Kubernetes has no server-side TTL, so correctness never relies on deletion: reads compare
//! `expiresAt` with the clock and writes treat an expired object as absent. A background sweeper
//! owned by the store deletes expired objects so that etcd does not fill up.
//!
//! The compare-and-swap primitive is the object's `resourceVersion`: `PUT` with the version that
//! was read, and `DELETE` with a `resourceVersion` precondition, fail with 409 if the object
//! changed in between. A `GET` without a `resourceVersion` is a quorum read, so reads are
//! linearizable.
//!
//! The API client is wrapped by the small [`KubernetesClient`] trait so the store's logic is
//! tested against a fake; [`KubeClient`] is the production implementation over `kube`.

use async_trait::async_trait;
use oauthrelay_core::{validate_key, validate_ttl, Entry, StoreError, TransientStore};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod crd;
mod kube_client;
mod mapping;

pub use crd::{TransientRecord, TransientRecordSpec};
pub use kube_client::KubeClient;
pub use mapping::{
    object_name, RecordMapping, MANAGED_BY_LABEL, MANAGED_BY_VALUE, MANAGED_SELECTOR, NAME_PREFIX,
    PURPOSE_LABEL,
};

/// Objects requested per sweeper list call.
pub const SWEEP_PAGE_SIZE: u32 = 500;
/// Attempts, each a conflicting write, that `put_if_absent` spends replacing an expired record
/// before it reports the key as taken.
const REPLACE_ROUNDS: usize = 3;

/// Deterministic, installable CRD for the [`TransientRecord`] mapping.
pub fn crds_yaml() -> anyhow::Result<String> {
    use kube::CustomResourceExt;
    Ok(serde_saphyr::to_string(&TransientRecord::crd())?)
}

/// A record as stored in the cluster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stored {
    pub name: String,
    pub resource_version: String,
    pub value: Vec<u8>,
    /// Unix epoch milliseconds.
    pub expires_at_ms: u64,
}

/// A record to write. `name` is [`object_name`] of `key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewRecord<'a> {
    pub name: &'a str,
    pub key: &'a str,
    pub value: &'a [u8],
    /// Unix epoch milliseconds.
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateOutcome {
    Created,
    /// 409: an object with this name exists. This can also be the outcome of a request that *did*
    /// apply and whose response was lost.
    AlreadyExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaceOutcome {
    Replaced,
    /// 409: the object changed since the `resourceVersion` that was supplied.
    Conflict,
    /// 404: the object does not exist.
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    Deleted,
    /// 409: the object changed since the `resourceVersion` precondition.
    Conflict,
    /// 404: the object does not exist.
    NotFound,
}

/// One page of a list.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Page {
    pub items: Vec<Stored>,
    /// Names of listed objects that do not decode as a record.
    pub undecodable: Vec<String>,
    /// Pass back to fetch the next page; `None` on the last one.
    pub continue_token: Option<String>,
}

/// The object operations the store needs, bound to one resource in one namespace.
#[async_trait]
pub trait KubernetesClient: Send + Sync + 'static {
    /// The resource and namespace, for messages.
    fn target(&self) -> String;
    /// Quorum `GET` by name. An object that exists but does not decode is an error.
    async fn get(&self, name: &str) -> anyhow::Result<Option<Stored>>;
    /// `POST` a new object.
    async fn create(&self, record: NewRecord<'_>) -> anyhow::Result<CreateOutcome>;
    /// `PUT` the whole object, conditional on `resource_version`.
    async fn replace(
        &self,
        record: NewRecord<'_>,
        resource_version: &str,
    ) -> anyhow::Result<ReplaceOutcome>;
    /// `DELETE` by name, with a `resourceVersion` precondition when one is given.
    async fn delete(
        &self,
        name: &str,
        resource_version: Option<&str>,
    ) -> anyhow::Result<DeleteOutcome>;
    /// One page of a `LIST` restricted by a label selector.
    async fn list(
        &self,
        label_selector: &str,
        limit: u32,
        continue_token: Option<&str>,
    ) -> anyhow::Result<Page>;
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// What one [`KubernetesStore::sweep`] pass did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SweepReport {
    /// Objects the pass listed.
    pub listed: usize,
    /// Expired objects it deleted.
    pub deleted: usize,
    /// Expired objects it left because they changed between the list and the delete: another
    /// replica renewed or already removed them.
    pub skipped: usize,
}

struct Inner<C> {
    client: Arc<C>,
    clock: Clock,
}

/// [`TransientStore`] over Kubernetes custom resources.
///
/// Expiry is judged by the reading replica's clock, so replicas are assumed to have clocks
/// synchronized to within a second or so, as with the DynamoDB backend. Records keep millisecond
/// precision. [`KubernetesStore::with_sweeper`] starts the background sweeper, which the store
/// stops when it is dropped.
pub struct KubernetesStore<C: KubernetesClient> {
    inner: Arc<Inner<C>>,
    sweeper: Option<tokio::task::JoinHandle<()>>,
}

impl<C: KubernetesClient> KubernetesStore<C> {
    pub fn new(client: Arc<C>) -> Self {
        Self::with_clock(client, Arc::new(unix_millis))
    }

    /// Uses `clock` (Unix epoch milliseconds) instead of the system clock.
    pub fn with_clock(client: Arc<C>, clock: Clock) -> Self {
        Self {
            inner: Arc::new(Inner { client, clock }),
            sweeper: None,
        }
    }

    /// Starts a task that runs [`KubernetesStore::sweep`] every `interval`, replacing a running
    /// one. Must be called within a Tokio runtime.
    pub fn with_sweeper(mut self, interval: Duration) -> Self {
        if let Some(previous) = self.sweeper.take() {
            previous.abort();
        }
        let inner = self.inner.clone();
        self.sweeper = Some(tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match inner.sweep().await {
                    Ok(report) if report.deleted > 0 => tracing::debug!(
                        resource = %inner.client.target(),
                        deleted = report.deleted,
                        "swept expired transient records"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        resource = %inner.client.target(),
                        ?error,
                        "transient record sweep failed"
                    ),
                }
            }
        }));
        self
    }

    /// Checks that the resource is served and that the credentials may list it: a `LIST` of at
    /// most one object. Call it at startup so a missing CRD or a missing RBAC rule is reported
    /// then, not on the first token request.
    pub async fn probe(&self) -> anyhow::Result<()> {
        use anyhow::Context;
        self.inner
            .client
            .list(MANAGED_SELECTOR, 1, None)
            .await
            .with_context(|| {
                format!(
                    "cannot list {}: install the CRD and grant get, list, create, update and delete on it",
                    self.inner.client.target()
                )
            })?;
        Ok(())
    }

    /// Deletes every expired object this store manages, once. An object that changed between
    /// the list and its delete (a record renewed by another replica) is left alone.
    pub async fn sweep(&self) -> anyhow::Result<SweepReport> {
        self.inner.sweep().await
    }
}

impl<C: KubernetesClient> Drop for KubernetesStore<C> {
    fn drop(&mut self) {
        if let Some(sweeper) = self.sweeper.take() {
            sweeper.abort();
        }
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl<C: KubernetesClient> Inner<C> {
    fn now(&self) -> u64 {
        (self.clock)()
    }

    async fn sweep(&self) -> anyhow::Result<SweepReport> {
        let mut report = SweepReport::default();
        let mut continue_token = None;
        loop {
            let page = self
                .client
                .list(MANAGED_SELECTOR, SWEEP_PAGE_SIZE, continue_token.as_deref())
                .await?;
            let now = self.now();
            report.listed += page.items.len();
            for name in &page.undecodable {
                tracing::warn!(%name, resource = %self.client.target(), "managed object is not a valid transient record; leaving it");
            }
            for object in page
                .items
                .iter()
                .filter(|object| object.expires_at_ms <= now)
            {
                match self
                    .client
                    .delete(&object.name, Some(&object.resource_version))
                    .await?
                {
                    DeleteOutcome::Deleted => report.deleted += 1,
                    DeleteOutcome::Conflict | DeleteOutcome::NotFound => report.skipped += 1,
                }
            }
            match page.continue_token.filter(|token| !token.is_empty()) {
                Some(token) => continue_token = Some(token),
                None => return Ok(report),
            }
        }
    }

    /// The expiry for a record written now, in Unix epoch milliseconds.
    fn expiry(&self, now: u64, ttl: Duration) -> Result<u64, StoreError> {
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        now.checked_add(ttl_ms)
            .filter(|expiry| *expiry <= mapping::max_expiry_millis())
            .ok_or_else(|| StoreError::Invalid("ttl is too large".into()))
    }

    /// Whether `object` is the live record that this call wrote: holding exactly `written`.
    ///
    /// A 409 is ambiguous: a request whose response was lost and which was then retried reports a
    /// conflict for a write that applied. If the object now holds exactly the value this call
    /// wrote, and is still live, the write is ours. That is exact only if every value written to
    /// a key is unique among its writers, which is a caller obligation of [`TransientStore`]:
    /// oauthrelay seals every record value with a random nonce.
    fn is_ours(object: &Option<Stored>, written: &[u8], now: u64) -> bool {
        object
            .as_ref()
            .is_some_and(|object| object.expires_at_ms > now && object.value == written)
    }
}

#[async_trait]
impl<C: KubernetesClient> TransientStore for KubernetesStore<C> {
    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        validate_key(key)?;
        validate_ttl(ttl)?;
        let inner = &*self.inner;
        let name = object_name(key);
        let now = inner.now();
        let record = NewRecord {
            name: &name,
            key,
            value,
            expires_at_ms: inner.expiry(now, ttl)?,
        };
        for _ in 0..REPLACE_ROUNDS {
            let created = inner
                .client
                .create(record)
                .await
                .map_err(StoreError::Backend)?;
            if created == CreateOutcome::Created {
                return Ok(true);
            }
            let existing = inner.client.get(&name).await.map_err(StoreError::Backend)?;
            if Inner::<C>::is_ours(&existing, value, now) {
                return Ok(true);
            }
            let Some(existing) = existing else {
                // Deleted between the create and the read: try to create again.
                continue;
            };
            if existing.expires_at_ms > now {
                return Ok(false);
            }
            // An expired record counts as absent: take it over, unless it changed meanwhile.
            let replaced = inner
                .client
                .replace(record, &existing.resource_version)
                .await
                .map_err(StoreError::Backend)?;
            if replaced == ReplaceOutcome::Replaced {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        validate_key(key)?;
        let now = self.inner.now();
        let object = self
            .inner
            .client
            .get(&object_name(key))
            .await
            .map_err(StoreError::Backend)?;
        Ok(object
            .filter(|object| object.expires_at_ms > now)
            .map(|object| Entry {
                value: object.value,
                expires_in: Duration::from_millis(object.expires_at_ms - now),
            }))
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: &[u8],
        new: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        validate_key(key)?;
        validate_ttl(ttl)?;
        let inner = &*self.inner;
        let name = object_name(key);
        let now = inner.now();
        let expires_at_ms = inner.expiry(now, ttl)?;
        let current = inner.client.get(&name).await.map_err(StoreError::Backend)?;
        let Some(current) =
            current.filter(|current| current.expires_at_ms > now && current.value == expected)
        else {
            return Ok(false);
        };
        let record = NewRecord {
            name: &name,
            key,
            value: new,
            expires_at_ms,
        };
        let outcome = inner
            .client
            .replace(record, &current.resource_version)
            .await
            .map_err(StoreError::Backend)?;
        match outcome {
            ReplaceOutcome::Replaced => Ok(true),
            ReplaceOutcome::NotFound => Ok(false),
            ReplaceOutcome::Conflict => {
                let latest = inner.client.get(&name).await.map_err(StoreError::Backend)?;
                Ok(Inner::<C>::is_ours(&latest, new, now))
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        validate_key(key)?;
        self.inner
            .client
            .delete(&object_name(key), None)
            .await
            .map_err(StoreError::Backend)?;
        Ok(())
    }
}

#[cfg(test)]
mod kube_tests;
#[cfg(test)]
mod store_tests;
