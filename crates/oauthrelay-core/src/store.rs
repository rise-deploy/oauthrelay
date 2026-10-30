//! Transient key-value storage shared by replay protection and rotating refresh-token state.
//!
//! The router never holds durable state of its own: sealed envelopes carry their own contents. The
//! few facts that must be remembered across requests (a code was used, a handle was rotated) live
//! in a [`TransientStore`]. Every write carries a TTL, so the store only ever holds data that is
//! still relevant and needs no separate cleanup protocol.

use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use thiserror::Error;

/// Longest accepted key. Backends may impose larger limits, but never smaller ones, so a key that
/// passes [`validate_key`] works everywhere. Callers hash user-influenced material into keys.
pub const MAX_KEY_BYTES: usize = 1024;

#[derive(Debug, Error)]
pub enum StoreError {
    /// The request violates the contract (empty or oversized key, zero TTL); retrying cannot help.
    #[error("invalid transient store request: {0}")]
    Invalid(String),
    /// The backend failed or was unreachable. The outcome of the operation is unknown.
    #[error("transient store backend failed: {0:#}")]
    Backend(#[source] anyhow::Error),
}

/// A live (unexpired) record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub value: Vec<u8>,
    /// Time left until the record expires, as measured by the backend's clock when it was read.
    pub expires_in: Duration,
}

/// Expiring key-value storage with the atomic primitives that single-use and rotation protocols
/// need. Values are opaque bytes; callers own their encoding.
///
/// # Contract
///
/// - Keys are non-empty UTF-8 of at most [`MAX_KEY_BYTES`] bytes, namespaced by their callers with
///   a purpose prefix (`replay:`, `refresh:`, ...). Backends treat keys as opaque and never add or
///   interpret prefixes. TTLs are non-zero.
/// - Operations on one key are linearizable across every instance sharing the backend: a successful
///   write is visible to every later `get`, and `put_if_absent` / `compare_and_swap` each succeed
///   for exactly one of any set of concurrent callers.
/// - A record stays visible for at least its TTL. A backend with a coarse clock (DynamoDB stores
///   whole seconds) may keep it a couple of seconds longer; either way `get` and the conditional
///   writes treat an expired record as absent even if the backend has not physically removed it.
/// - Callers write values that are unique to the writer (for example sealed with a random nonce
///   or carrying a random claim id), never a constant shared by several writers. A backend whose
///   conditional write can fail ambiguously after applying (DynamoDB behind SDK retries) resolves
///   the ambiguity by checking whether the stored value is the one it just wrote; that is exact
///   only when no other writer could have written the same bytes.
/// - An `Err` means the outcome is unknown. Callers fail closed: a replay check that errors rejects
///   the request.
///
/// # Refresh-token rotation usage
///
/// A `rotating` relay keeps one record per refresh-token handle (key `refresh:handle:{hash}`,
/// where the hash covers the relay key and the handle, so neither can be read back from the
/// store) and one marker per revoked family. Values are sealed by the relay, so the store only
/// ever holds opaque bytes. The protocol uses exactly these four operations:
///
/// 1. *Issue.* `put_if_absent` creates the handle's record in the `Active` state with a TTL that
///    ends with the family's maximum lifetime.
/// 2. *Claim.* The presenter reads the record and `compare_and_swap`s the bytes it read for a
///    `Claimed` value carrying a random claim id. Exactly one concurrent presenter wins and
///    performs the upstream refresh. The compare is on the whole value, and every value is
///    sealed with a random nonce, so no two writes ever produce equal bytes: a stale claimant
///    can never match a value somebody else wrote.
/// 3. *Record the successor.* The successor's record is created with `put_if_absent` and the
///    response returned to the client is stored under a key derived from the old handle and the
///    claim id (TTL: the grace period plus a small margin). Only then does `compare_and_swap`
///    turn the old record into a `Rotated` tombstone (rotation time and claim id, no token) that
///    stays until the family expires, so a replay is recognised for the family's whole life.
/// 4. *Racing duplicate.* A presenter that finds the record `Claimed` polls it with `get` for a
///    few seconds. A `Rotated` record within the grace period is answered with the stored
///    response, so the duplicate receives the same successor.
/// 5. *Release.* If the upstream refresh fails, `compare_and_swap(claimed, fresh Active value)`
///    makes the handle claimable again. The value is new rather than a "released" marker; the
///    unique bytes serve the same purpose. A claim older than a lease (60 seconds) is presumed
///    abandoned and is replaced the same way.
/// 6. *Reuse and revocation.* A `Rotated` record presented after its grace period is a replay:
///    `put_if_absent("refresh:revoked:{hash}", ..)` marks the family revoked for the rest of its
///    lifetime. Every refresh checks that key first. An upstream `invalid_grant` revokes the
///    family the same way.
///
/// Expiry bounds all of this state, so no sweeper is required.
#[async_trait]
pub trait TransientStore: Send + Sync + 'static {
    /// Atomically store `value` under `key` for `ttl` if no live record exists; return whether it
    /// was stored. An expired record counts as absent. Used for single-use claims.
    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError>;

    /// Read the live record for `key`, if any. The read is strongly consistent.
    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError>;

    /// Atomically replace the live record's value with `new` and restart its TTL, only if its
    /// current value equals `expected`; return whether it was replaced. An absent or expired
    /// record never matches, so create records with [`TransientStore::put_if_absent`].
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: &[u8],
        new: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError>;

    /// Remove the record for `key`. Removing an absent record succeeds.
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// Rejects keys that would not be accepted by every backend.
pub fn validate_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() {
        return Err(StoreError::Invalid("key must not be empty".into()));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(StoreError::Invalid(format!(
            "key exceeds {MAX_KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Rejects a zero TTL, which would create a record that is never visible.
pub fn validate_ttl(ttl: Duration) -> Result<(), StoreError> {
    if ttl.is_zero() {
        return Err(StoreError::Invalid("ttl must be greater than zero".into()));
    }
    Ok(())
}

const MEMORY_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct MemoryRecord {
    value: Vec<u8>,
    expires: Instant,
}

struct MemoryState {
    records: HashMap<String, MemoryRecord>,
    next_sweep: Instant,
}

/// In-process store. State is private to one process: it protects one native server or one warm
/// Lambda execution environment and is lost on restart.
///
/// Expired records are ignored on access and removed in a full pass at most every 30 seconds, so
/// memory is bounded by the write rate over the longest TTL plus that interval.
pub struct MemoryStore {
    state: Mutex<MemoryState>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }
}

impl MemoryStore {
    fn with_clock(clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        let next_sweep = clock() + MEMORY_SWEEP_INTERVAL;
        Self {
            state: Mutex::new(MemoryState {
                records: HashMap::new(),
                next_sweep,
            }),
            clock,
        }
    }

    /// Locks the state and removes expired records when a sweep is due. Returns the current time.
    fn lock(&self) -> (MutexGuard<'_, MemoryState>, Instant) {
        let now = (self.clock)();
        // Every critical section leaves the map consistent, so poisoning carries no information.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if now >= state.next_sweep {
            state.records.retain(|_, record| record.expires > now);
            state.next_sweep = now + MEMORY_SWEEP_INTERVAL;
        }
        (state, now)
    }
}

#[async_trait]
impl TransientStore for MemoryStore {
    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        validate_key(key)?;
        validate_ttl(ttl)?;
        let (mut state, now) = self.lock();
        if state
            .records
            .get(key)
            .is_some_and(|record| record.expires > now)
        {
            return Ok(false);
        }
        state.records.insert(
            key.to_owned(),
            MemoryRecord {
                value: value.to_vec(),
                expires: now + ttl,
            },
        );
        Ok(true)
    }

    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        validate_key(key)?;
        let (state, now) = self.lock();
        Ok(state
            .records
            .get(key)
            .filter(|record| record.expires > now)
            .map(|record| Entry {
                value: record.value.clone(),
                expires_in: record.expires - now,
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
        let (mut state, now) = self.lock();
        match state.records.get_mut(key) {
            Some(record) if record.expires > now && record.value == expected => {
                record.value = new.to_vec();
                record.expires = now + ttl;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        validate_key(key)?;
        let (mut state, _) = self.lock();
        state.records.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    struct FakeClock(Mutex<Instant>);

    impl FakeClock {
        fn store() -> (Arc<FakeClock>, MemoryStore) {
            let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
            let source = clock.clone();
            let store = MemoryStore::with_clock(Arc::new(move || *source.0.lock().unwrap()));
            (clock, store)
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    #[tokio::test]
    async fn put_if_absent_admits_only_the_first_writer() {
        let store = MemoryStore::default();
        assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
        assert!(!store.put_if_absent("replay:a", b"2", TTL).await.unwrap());
        assert!(store.put_if_absent("replay:b", b"1", TTL).await.unwrap());
        let entry = store.get("replay:a").await.unwrap().unwrap();
        assert_eq!(entry.value, b"1");
        assert!(entry.expires_in <= TTL);
    }

    #[tokio::test]
    async fn concurrent_put_if_absent_has_one_winner() {
        let store = Arc::new(MemoryStore::default());
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move { store.put_if_absent("k", b"v", TTL).await.unwrap() })
            })
            .collect();
        let mut winners = 0;
        for task in tasks {
            winners += usize::from(task.await.unwrap());
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn expired_records_are_absent_and_can_be_recreated() {
        let (clock, store) = FakeClock::store();
        assert!(store.put_if_absent("k", b"old", TTL).await.unwrap());
        clock.advance(TTL - Duration::from_millis(1));
        assert!(store.get("k").await.unwrap().is_some());
        assert!(!store.put_if_absent("k", b"x", TTL).await.unwrap());
        clock.advance(Duration::from_millis(1));
        assert!(store.get("k").await.unwrap().is_none());
        assert!(!store
            .compare_and_swap("k", b"old", b"new", TTL)
            .await
            .unwrap());
        assert!(store.put_if_absent("k", b"fresh", TTL).await.unwrap());
        assert_eq!(store.get("k").await.unwrap().unwrap().value, b"fresh");
    }

    #[tokio::test]
    async fn compare_and_swap_requires_the_current_value_and_restarts_the_ttl() {
        let (clock, store) = FakeClock::store();
        assert!(!store.compare_and_swap("k", b"a", b"b", TTL).await.unwrap());
        store.put_if_absent("k", b"a", TTL).await.unwrap();
        assert!(!store
            .compare_and_swap("k", b"other", b"b", TTL)
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap().unwrap().value, b"a");
        clock.advance(Duration::from_secs(40));
        assert!(store.compare_and_swap("k", b"a", b"b", TTL).await.unwrap());
        // The old value no longer matches, so a second claimant loses.
        assert!(!store.compare_and_swap("k", b"a", b"c", TTL).await.unwrap());
        let entry = store.get("k").await.unwrap().unwrap();
        assert_eq!(entry.value, b"b");
        assert_eq!(entry.expires_in, TTL);
        clock.advance(Duration::from_secs(40));
        assert!(store.get("k").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_removes_records_and_tolerates_absent_keys() {
        let store = MemoryStore::default();
        store.delete("missing").await.unwrap();
        store.put_if_absent("k", b"v", TTL).await.unwrap();
        store.delete("k").await.unwrap();
        assert!(store.get("k").await.unwrap().is_none());
        assert!(store.put_if_absent("k", b"v", TTL).await.unwrap());
    }

    #[tokio::test]
    async fn periodic_sweep_discards_expired_records() {
        let (clock, store) = FakeClock::store();
        for index in 0..10 {
            store
                .put_if_absent(&format!("k{index}"), b"v", Duration::from_secs(1))
                .await
                .unwrap();
        }
        assert_eq!(store.state.lock().unwrap().records.len(), 10);
        clock.advance(MEMORY_SWEEP_INTERVAL);
        store.get("unrelated").await.unwrap();
        assert!(store.state.lock().unwrap().records.is_empty());
    }

    #[tokio::test]
    async fn invalid_requests_are_rejected() {
        let store = MemoryStore::default();
        let too_long = "k".repeat(MAX_KEY_BYTES + 1);
        for key in ["", too_long.as_str()] {
            assert!(matches!(
                store.put_if_absent(key, b"v", TTL).await,
                Err(StoreError::Invalid(_))
            ));
            assert!(matches!(store.get(key).await, Err(StoreError::Invalid(_))));
            assert!(matches!(
                store.compare_and_swap(key, b"a", b"b", TTL).await,
                Err(StoreError::Invalid(_))
            ));
            assert!(matches!(
                store.delete(key).await,
                Err(StoreError::Invalid(_))
            ));
        }
        assert!(matches!(
            store.put_if_absent("k", b"v", Duration::ZERO).await,
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store
                .compare_and_swap("k", b"a", b"b", Duration::ZERO)
                .await,
            Err(StoreError::Invalid(_))
        ));
        store
            .put_if_absent(&"k".repeat(MAX_KEY_BYTES), b"v", TTL)
            .await
            .unwrap();
    }

    /// Walks the rotation protocol described on [`TransientStore`] to show the four operations
    /// are sufficient.
    #[tokio::test]
    async fn supports_the_documented_rotation_protocol() {
        let store = MemoryStore::default();
        let handle = "refresh:handle:h1";
        let family = "refresh:revoked:f1";
        let active = b"active:1";
        assert!(store.put_if_absent(handle, active, TTL).await.unwrap());
        // Two presenters race to claim the record they both read: exactly one wins.
        assert!(store
            .compare_and_swap(handle, active, b"claimed:A", TTL)
            .await
            .unwrap());
        assert!(!store
            .compare_and_swap(handle, active, b"claimed:B", TTL)
            .await
            .unwrap());
        // The loser reads the claim; the winner records the successor.
        assert_eq!(
            store.get(handle).await.unwrap().unwrap().value,
            b"claimed:A"
        );
        assert!(store
            .compare_and_swap(handle, b"claimed:A", b"rotated:A", TTL)
            .await
            .unwrap());
        // A stale claimant cannot overwrite the rotation, and a release only matches its own claim.
        assert!(!store
            .compare_and_swap(handle, b"claimed:A", b"active:2", TTL)
            .await
            .unwrap());
        assert_eq!(
            store.get(handle).await.unwrap().unwrap().value,
            b"rotated:A"
        );
        // Reuse revokes the family exactly once.
        assert!(store.get(family).await.unwrap().is_none());
        assert!(store.put_if_absent(family, b"1", TTL).await.unwrap());
        assert!(!store.put_if_absent(family, b"1", TTL).await.unwrap());
        assert!(store.get(family).await.unwrap().is_some());
        store.delete(family).await.unwrap();
        assert!(store.get(family).await.unwrap().is_none());
    }
}
