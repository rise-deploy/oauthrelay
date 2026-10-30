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
//! namespace ([`REQUIRED_VERBS`]); [`KubernetesStore::probe`] checks them at startup.
//!
//! Kubernetes has no server-side TTL, so correctness never relies on deletion: reads compare
//! `expiresAt` with the clock and writes treat an expired object as absent. A background sweeper
//! owned by the store deletes expired objects so that etcd does not fill up. Every record also
//! carries an `oauthrelay.dev/expires-hour` label (the unix hour of its expiry), so a sweep lists
//! only the hours that can hold expired records instead of every record; see
//! [`KubernetesStore::with_sweeper`].
//!
//! Every store operation has a deadline ([`OPERATION_DEADLINE`]) after which it fails with
//! [`StoreError::Backend`], whatever the API server is doing.
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
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod crd;
mod kube_client;
mod mapping;

pub use crd::{TransientRecord, TransientRecordSpec};
pub use kube_client::KubeClient;
pub use mapping::{
    expiry_hour, expiry_selector, object_name, RecordMapping, EXPIRES_HOUR_LABEL, EXPIRY_BUCKET_MS,
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, MANAGED_SELECTOR, NAME_PREFIX, PURPOSE_LABEL,
};

/// Objects requested per sweeper list call.
pub const SWEEP_PAGE_SIZE: u32 = 500;
/// The longest a [`TransientStore`] operation may take, API requests included, before it fails
/// with [`StoreError::Backend`]. The outcome of a write that hit the deadline is unknown. It is
/// well below the 60 s claim lease, so a caller that stalls on the store does not hold a claim
/// past its lease.
pub const OPERATION_DEADLINE: Duration = Duration::from_secs(10);
/// How long past its expiry a record must be before the sweeper deletes it. Reads and writes
/// judge expiry exactly; the grace keeps a replica whose clock runs ahead from deleting records
/// that its peers still treat as live.
pub const SWEEP_GRACE: Duration = Duration::from_secs(30);
/// How often a sweeper repeats the full pass over every managed object, which catches records
/// the expiry buckets missed: those written without the label, or with a clock far behind.
pub const FULL_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 3600);
/// Expiry hours per bucket list request, which carry them in the label selector.
const HOURS_PER_LIST: usize = 20;
/// The verbs the store needs on its resource.
pub const REQUIRED_VERBS: [&str; 5] = ["get", "list", "create", "update", "delete"];
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
    /// What must hold for the resource to be served, completing "check that ...", for the
    /// startup message that explains a failed list.
    fn install_hint(&self) -> String;
    /// Whether the credentials may perform `verb` on the resource in the namespace, from a
    /// `SelfSubjectAccessReview`.
    async fn permits(&self, verb: &str) -> anyhow::Result<bool>;
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

/// Where the sweeper stands.
#[derive(Clone, Copy, Debug)]
struct SweepState {
    /// Every record that expires in an earlier hour was deleted or renewed by the last pass that
    /// covered it.
    watermark_hour: u64,
    /// When the last full pass started, in Unix epoch milliseconds.
    last_full_ms: u64,
}

struct Inner<C> {
    client: Arc<C>,
    clock: Clock,
    /// `None` until the first sweep, which is a full pass.
    sweep_state: Mutex<Option<SweepState>>,
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
            inner: Arc::new(Inner {
                client,
                clock,
                sweep_state: Mutex::new(None),
            }),
            sweeper: None,
        }
    }

    /// Starts a task that sweeps expired records every `interval`, replacing a running one. Must
    /// be called within a Tokio runtime.
    ///
    /// The first sweep is a full pass over every managed object, which also deletes records
    /// written before the expiry label existed. After it, each sweep lists only the objects whose
    /// `oauthrelay.dev/expires-hour` label is an hour that can hold expired records: from a
    /// watermark that the sweeper keeps in memory up to the hour of `now` minus [`SWEEP_GRACE`].
    /// A full pass repeats every [`FULL_SWEEP_INTERVAL`] as a backstop. A sweep that fails leaves
    /// the watermark where it was.
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
                match inner.sweep_tick().await {
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

    /// Checks at startup, so that problems are reported then and not on the first token request,
    /// that the resource is served and that the credentials hold every verb in
    /// [`REQUIRED_VERBS`]: a `LIST` of at most one object, then a `SelfSubjectAccessReview` per
    /// verb. The error names the verbs that are missing.
    pub async fn probe(&self) -> anyhow::Result<()> {
        use anyhow::Context;
        let client = &self.inner.client;
        let target = client.target();
        self.inner
            .bounded_call("list", client.list(MANAGED_SELECTOR, 1, None))
            .await
            .with_context(|| {
                format!(
                    "cannot list {target}: check that {} and that the role grants {} on it",
                    client.install_hint(),
                    REQUIRED_VERBS.join(", "),
                )
            })?;
        let mut missing = Vec::new();
        for verb in REQUIRED_VERBS {
            let allowed = self
                .inner
                .bounded_call("access review", client.permits(verb))
                .await
                .with_context(|| {
                    format!("cannot check whether the role may {verb} {target} (SelfSubjectAccessReview)")
                })?;
            if !allowed {
                missing.push(verb);
            }
        }
        if !missing.is_empty() {
            anyhow::bail!(
                "the role lacks {} on {target}: it needs {}",
                missing.join(", "),
                REQUIRED_VERBS.join(", "),
            );
        }
        Ok(())
    }

    /// Deletes every object this store manages that expired more than [`SWEEP_GRACE`] ago, once,
    /// in a full pass over all of them. An object that changed between the list and its delete
    /// (a record renewed by another replica) is left alone.
    pub async fn sweep(&self) -> anyhow::Result<SweepReport> {
        self.inner.full_sweep().await
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

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl<C: KubernetesClient> Inner<C> {
    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Runs `operation` for at most [`OPERATION_DEADLINE`], so that a slow or unresponsive API
    /// server surfaces as an error instead of a stall.
    async fn bounded_call<T>(
        &self,
        operation: &str,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        match tokio::time::timeout(OPERATION_DEADLINE, future).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "{operation} on {} did not finish within {}s; whether it took effect is unknown",
                self.client.target(),
                OPERATION_DEADLINE.as_secs()
            )),
        }
    }

    /// [`Inner::bounded_call`] for a whole [`TransientStore`] operation, which may make several
    /// API requests.
    async fn bounded<T>(
        &self,
        operation: &str,
        future: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        match self
            .bounded_call(operation, async { Ok(future.await) })
            .await
        {
            Ok(result) => result,
            Err(error) => Err(StoreError::Backend(error)),
        }
    }

    /// The latest hour whose records can be deleted at `now`, which is also the first hour that
    /// is not yet entirely in the past: every record in an earlier hour is past the grace.
    fn settled_hour(now: u64) -> u64 {
        expiry_hour(now.saturating_sub(millis(SWEEP_GRACE)))
    }

    /// A full pass, which restarts the watermark and the backstop interval.
    async fn full_sweep(&self) -> anyhow::Result<SweepReport> {
        let started = self.now();
        let report = self.sweep_selector(MANAGED_SELECTOR).await?;
        *self.sweep_state.lock().unwrap() = Some(SweepState {
            watermark_hour: Self::settled_hour(started),
            last_full_ms: started,
        });
        Ok(report)
    }

    /// One tick of the sweeper: a full pass when none has run yet or the backstop is due, else
    /// the expiry hours from the watermark on.
    async fn sweep_tick(&self) -> anyhow::Result<SweepReport> {
        let now = self.now();
        let state = *self.sweep_state.lock().unwrap();
        let Some(state) = state
            .filter(|state| now.saturating_sub(state.last_full_ms) < millis(FULL_SWEEP_INTERVAL))
        else {
            return self.full_sweep().await;
        };
        // The window is at most a day and an hour: the watermark is no older than the last full
        // pass, and a full pass is due a day after it.
        let last = Self::settled_hour(now);
        let hours: Vec<u64> = (state.watermark_hour..=last).collect();
        let mut report = SweepReport::default();
        for chunk in hours.chunks(HOURS_PER_LIST) {
            let part = self
                .sweep_selector(&expiry_selector(chunk.iter().copied()))
                .await?;
            report.listed += part.listed;
            report.deleted += part.deleted;
            report.skipped += part.skipped;
        }
        if let Some(current) = self.sweep_state.lock().unwrap().as_mut() {
            current.watermark_hour = current.watermark_hour.max(last);
        }
        Ok(report)
    }

    /// Lists the objects matching `selector`, page by page, and deletes those expired by more
    /// than the grace. `selector` always contains the managed-by selector.
    async fn sweep_selector(&self, selector: &str) -> anyhow::Result<SweepReport> {
        let mut report = SweepReport::default();
        let mut continue_token = None;
        loop {
            let page = self
                .bounded_call(
                    "list",
                    self.client
                        .list(selector, SWEEP_PAGE_SIZE, continue_token.as_deref()),
                )
                .await?;
            let now = self.now();
            report.listed += page.items.len();
            for name in &page.undecodable {
                tracing::warn!(%name, resource = %self.client.target(), "managed object is not a valid transient record; leaving it");
            }
            for object in page
                .items
                .iter()
                .filter(|object| object.expires_at_ms.saturating_add(millis(SWEEP_GRACE)) <= now)
            {
                match self
                    .bounded_call(
                        "delete",
                        self.client
                            .delete(&object.name, Some(&object.resource_version)),
                    )
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
        now.checked_add(millis(ttl))
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

    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        let name = object_name(key);
        let now = self.now();
        let record = NewRecord {
            name: &name,
            key,
            value,
            expires_at_ms: self.expiry(now, ttl)?,
        };
        for _ in 0..REPLACE_ROUNDS {
            let created = self
                .client
                .create(record)
                .await
                .map_err(StoreError::Backend)?;
            if created == CreateOutcome::Created {
                return Ok(true);
            }
            let existing = self.client.get(&name).await.map_err(StoreError::Backend)?;
            if Self::is_ours(&existing, value, now) {
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
            let replaced = self
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
        let now = self.now();
        let object = self
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
        let name = object_name(key);
        let now = self.now();
        let expires_at_ms = self.expiry(now, ttl)?;
        let current = self.client.get(&name).await.map_err(StoreError::Backend)?;
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
        let outcome = self
            .client
            .replace(record, &current.resource_version)
            .await
            .map_err(StoreError::Backend)?;
        match outcome {
            ReplaceOutcome::Replaced => Ok(true),
            ReplaceOutcome::NotFound => Ok(false),
            ReplaceOutcome::Conflict => {
                let latest = self.client.get(&name).await.map_err(StoreError::Backend)?;
                Ok(Self::is_ours(&latest, new, now))
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.client
            .delete(&object_name(key), None)
            .await
            .map_err(StoreError::Backend)?;
        Ok(())
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
        let inner = &self.inner;
        inner
            .bounded("put_if_absent", inner.put_if_absent(key, value, ttl))
            .await
    }

    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        validate_key(key)?;
        let inner = &self.inner;
        inner.bounded("get", inner.get(key)).await
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
        let inner = &self.inner;
        inner
            .bounded(
                "compare_and_swap",
                inner.compare_and_swap(key, expected, new, ttl),
            )
            .await
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        validate_key(key)?;
        let inner = &self.inner;
        inner.bounded("delete", inner.delete(key)).await
    }
}

#[cfg(test)]
mod kube_tests;
#[cfg(test)]
mod store_tests;
