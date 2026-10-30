//! Amazon DynamoDB backend for oauthrelay's [`TransientStore`].
//!
//! Every record is one item in a table whose partition key is the store key. Table schema:
//!
//! | Attribute | Type | Meaning |
//! | --- | --- | --- |
//! | `pk` | String, partition key (no sort key) | The store key. |
//! | `value` | Binary | The opaque record value. |
//! | `expires_at` | Number | Expiry as Unix epoch seconds. Configure it as the table's TTL attribute. |
//!
//! The runtime role needs `dynamodb:PutItem`, `dynamodb:GetItem` and `dynamodb:DeleteItem` on the
//! table.
//!
//! DynamoDB deletes expired items lazily, often hours after expiry, so correctness never relies on
//! TTL deletion: reads compare `expires_at` with the clock and conditional writes treat an expired
//! item as absent. TTL deletion only reclaims storage.
//!
//! The SDK client is wrapped by the small [`DynamoDbClient`] trait so the store's logic is tested
//! against a fake; [`AwsDynamoDbClient`] is the production implementation.

use async_trait::async_trait;
use oauthrelay_core::{validate_key, validate_ttl, Entry, StoreError, TransientStore};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Partition key attribute name.
pub const KEY_ATTRIBUTE: &str = "pk";
/// Binary value attribute name.
pub const VALUE_ATTRIBUTE: &str = "value";
/// Epoch-seconds expiry attribute name; the table's TTL attribute.
pub const EXPIRES_ATTRIBUTE: &str = "expires_at";

/// One stored record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Item {
    pub value: Vec<u8>,
    /// Unix epoch seconds.
    pub expires_at: u64,
}

/// When a [`DynamoDbClient::put_item`] may overwrite the existing item. `now` is epoch seconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PutCondition {
    /// `attribute_not_exists(pk) OR expires_at <= now`: no live item exists.
    AbsentOrExpired { now: u64 },
    /// `expires_at > now AND value = expected`: a live item holds exactly this value.
    LiveWithValue { now: u64, expected: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutRequest {
    pub key: String,
    pub item: Item,
    pub condition: PutCondition,
}

/// The result of a conditional [`DynamoDbClient::put_item`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PutOutcome {
    /// The condition held and the item was written.
    Written,
    /// DynamoDB reported that the condition failed. `existing` is the item that was in the table
    /// at that moment (`ReturnValuesOnConditionCheckFailure=ALL_OLD`), `None` when the table
    /// returned none.
    ///
    /// This can also be the outcome of a request that *did* apply: the SDK retries a request whose
    /// response was lost, and the retry then fails against the item the first attempt wrote.
    ConditionFailed { existing: Option<Item> },
}

/// The three table operations the store needs, bound to one table.
#[async_trait]
pub trait DynamoDbClient: Send + Sync + 'static {
    /// Conditional `PutItem` that asks DynamoDB to return the existing item when the condition
    /// fails.
    async fn put_item(&self, request: PutRequest) -> anyhow::Result<PutOutcome>;
    /// Strongly consistent `GetItem`. Expired but not yet deleted items are returned as stored.
    async fn get_item(&self, key: &str) -> anyhow::Result<Option<Item>>;
    /// Unconditional `DeleteItem`; deleting an absent item succeeds.
    async fn delete_item(&self, key: &str) -> anyhow::Result<()>;
}

#[cfg(feature = "aws")]
pub use aws::AwsDynamoDbClient;

#[cfg(feature = "aws")]
mod aws;

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// [`TransientStore`] over DynamoDB.
///
/// DynamoDB stores whole seconds, so a record is kept for its TTL rounded up plus one second:
/// never shorter than requested, up to two seconds longer. Replicas are assumed to have clocks
/// synchronized to within a second or so; expiry is judged by the reading replica's clock.
pub struct DynamoDbStore<C> {
    client: Arc<C>,
    clock: Clock,
}

impl<C: DynamoDbClient> DynamoDbStore<C> {
    pub fn new(client: Arc<C>) -> Self {
        Self::with_clock(client, Arc::new(unix_now))
    }

    /// Uses `clock` (Unix epoch seconds) instead of the system clock.
    pub fn with_clock(client: Arc<C>, clock: Clock) -> Self {
        Self { client, clock }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Whether a conditional write took effect.
    ///
    /// A `ConditionalCheckFailed` is ambiguous: SDK retries can make a write that applied report a
    /// failure. If the item DynamoDB returned holds exactly the value this call wrote, and is
    /// still live, the write is ours and counts as successful. That is exact only if every value
    /// written to a key is unique among its writers, which is a caller obligation of
    /// [`TransientStore`]: oauthrelay seals every record value with a random nonce.
    fn applied(outcome: PutOutcome, written: &[u8], now: u64) -> bool {
        match outcome {
            PutOutcome::Written => true,
            PutOutcome::ConditionFailed { existing } => {
                existing.is_some_and(|item| item.value == written && item.expires_at > now)
            }
        }
    }

    fn expiry(&self, now: u64, ttl: Duration) -> u64 {
        let whole = ttl.as_secs() + u64::from(ttl.subsec_nanos() > 0);
        now.saturating_add(whole).saturating_add(1)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[async_trait]
impl<C: DynamoDbClient> TransientStore for DynamoDbStore<C> {
    async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        validate_key(key)?;
        validate_ttl(ttl)?;
        let now = self.now();
        let outcome = self
            .client
            .put_item(PutRequest {
                key: key.to_owned(),
                item: Item {
                    value: value.to_vec(),
                    expires_at: self.expiry(now, ttl),
                },
                condition: PutCondition::AbsentOrExpired { now },
            })
            .await
            .map_err(StoreError::Backend)?;
        Ok(Self::applied(outcome, value, now))
    }

    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        validate_key(key)?;
        let now = self.now();
        let item = self
            .client
            .get_item(key)
            .await
            .map_err(StoreError::Backend)?;
        Ok(item.filter(|item| item.expires_at > now).map(|item| Entry {
            value: item.value,
            expires_in: Duration::from_secs(item.expires_at - now),
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
        let now = self.now();
        let outcome = self
            .client
            .put_item(PutRequest {
                key: key.to_owned(),
                item: Item {
                    value: new.to_vec(),
                    expires_at: self.expiry(now, ttl),
                },
                condition: PutCondition::LiveWithValue {
                    now,
                    expected: expected.to_vec(),
                },
            })
            .await
            .map_err(StoreError::Backend)?;
        Ok(Self::applied(outcome, new, now))
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        validate_key(key)?;
        self.client
            .delete_item(key)
            .await
            .map_err(StoreError::Backend)
    }
}

#[cfg(test)]
mod store_tests;
