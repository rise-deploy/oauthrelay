use super::*;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

const START: u64 = 1_800_000_000;
const TTL: Duration = Duration::from_secs(60);

/// Applies each condition exactly as its documentation states, and records every request.
#[derive(Default)]
struct FakeClient {
    items: Mutex<HashMap<String, Item>>,
    puts: Mutex<Vec<PutRequest>>,
    gets: Mutex<Vec<String>>,
    deletes: Mutex<Vec<String>>,
    failing: AtomicBool,
}

impl FakeClient {
    fn check_available(&self) -> anyhow::Result<()> {
        if self.failing.load(Ordering::SeqCst) {
            anyhow::bail!("throttled");
        }
        Ok(())
    }

    fn calls(&self) -> usize {
        self.puts.lock().unwrap().len()
            + self.gets.lock().unwrap().len()
            + self.deletes.lock().unwrap().len()
    }
}

#[async_trait]
impl DynamoDbClient for FakeClient {
    async fn put_item(&self, request: PutRequest) -> anyhow::Result<bool> {
        self.check_available()?;
        self.puts.lock().unwrap().push(request.clone());
        let mut items = self.items.lock().unwrap();
        let existing = items.get(&request.key);
        let allowed = match &request.condition {
            PutCondition::AbsentOrExpired { now } => {
                existing.is_none_or(|item| item.expires_at <= *now)
            }
            PutCondition::LiveWithValue { now, expected } => {
                existing.is_some_and(|item| item.expires_at > *now && item.value == *expected)
            }
        };
        if allowed {
            items.insert(request.key, request.item);
        }
        Ok(allowed)
    }

    async fn get_item(&self, key: &str) -> anyhow::Result<Option<Item>> {
        self.check_available()?;
        self.gets.lock().unwrap().push(key.to_owned());
        Ok(self.items.lock().unwrap().get(key).cloned())
    }

    async fn delete_item(&self, key: &str) -> anyhow::Result<()> {
        self.check_available()?;
        self.deletes.lock().unwrap().push(key.to_owned());
        self.items.lock().unwrap().remove(key);
        Ok(())
    }
}

fn store() -> (Arc<FakeClient>, Arc<AtomicU64>, DynamoDbStore<FakeClient>) {
    let client = Arc::new(FakeClient::default());
    let now = Arc::new(AtomicU64::new(START));
    let source = now.clone();
    let store = DynamoDbStore::with_clock(
        client.clone(),
        Arc::new(move || source.load(Ordering::SeqCst)),
    );
    (client, now, store)
}

#[tokio::test]
async fn put_if_absent_sends_a_conditional_put_with_a_rounded_up_expiry() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    assert!(store
        .put_if_absent("replay:b", b"1", Duration::from_millis(1500))
        .await
        .unwrap());
    let puts = client.puts.lock().unwrap();
    assert_eq!(
        puts[0],
        PutRequest {
            key: "replay:a".into(),
            item: Item {
                value: b"1".to_vec(),
                expires_at: START + 60 + 1,
            },
            condition: PutCondition::AbsentOrExpired { now: START },
        }
    );
    // 1.5 s rounds up to 2 s, plus the second lost to the clock's truncation.
    assert_eq!(puts[1].item.expires_at, START + 2 + 1);
}

#[tokio::test]
async fn put_if_absent_rejects_a_live_record_but_replaces_an_expired_one() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("k", b"first", TTL).await.unwrap());
    assert!(!store.put_if_absent("k", b"second", TTL).await.unwrap());
    assert_eq!(client.items.lock().unwrap()["k"].value, b"first");
    // DynamoDB has not deleted the item yet, but its expiry has passed.
    now.store(START + 61, Ordering::SeqCst);
    assert!(client.items.lock().unwrap().contains_key("k"));
    assert!(store.put_if_absent("k", b"third", TTL).await.unwrap());
    assert_eq!(client.items.lock().unwrap()["k"].value, b"third");
}

#[tokio::test]
async fn get_hides_expired_items_that_ttl_deletion_has_not_removed() {
    let (client, now, store) = store();
    assert!(store.get("k").await.unwrap().is_none());
    store.put_if_absent("k", b"v", TTL).await.unwrap();
    now.store(START + 11, Ordering::SeqCst);
    assert_eq!(
        store.get("k").await.unwrap(),
        Some(Entry {
            value: b"v".to_vec(),
            expires_in: Duration::from_secs(50),
        })
    );
    now.store(START + 61, Ordering::SeqCst);
    assert!(client.items.lock().unwrap().contains_key("k"));
    assert!(store.get("k").await.unwrap().is_none());
}

#[tokio::test]
async fn compare_and_swap_requires_a_live_matching_item() {
    let (client, now, store) = store();
    assert!(!store.compare_and_swap("k", b"a", b"b", TTL).await.unwrap());
    store.put_if_absent("k", b"a", TTL).await.unwrap();
    assert!(!store.compare_and_swap("k", b"x", b"b", TTL).await.unwrap());
    now.store(START + 30, Ordering::SeqCst);
    assert!(store.compare_and_swap("k", b"a", b"b", TTL).await.unwrap());
    assert_eq!(
        client.puts.lock().unwrap().last().unwrap(),
        &PutRequest {
            key: "k".into(),
            item: Item {
                value: b"b".to_vec(),
                expires_at: START + 30 + 60 + 1,
            },
            condition: PutCondition::LiveWithValue {
                now: START + 30,
                expected: b"a".to_vec(),
            },
        }
    );
    // The first claimant has consumed the old value.
    assert!(!store.compare_and_swap("k", b"a", b"c", TTL).await.unwrap());
    // The swap restarted the TTL, and an expired item can no longer be swapped.
    now.store(START + 80, Ordering::SeqCst);
    assert!(store.get("k").await.unwrap().is_some());
    now.store(START + 30 + 61, Ordering::SeqCst);
    assert!(!store.compare_and_swap("k", b"b", b"c", TTL).await.unwrap());
}

#[tokio::test]
async fn delete_removes_the_item_and_tolerates_absence() {
    let (client, _, store) = store();
    store.delete("missing").await.unwrap();
    store.put_if_absent("k", b"v", TTL).await.unwrap();
    store.delete("k").await.unwrap();
    assert!(store.get("k").await.unwrap().is_none());
    assert_eq!(*client.deletes.lock().unwrap(), ["missing", "k"]);
}

#[tokio::test]
async fn invalid_requests_never_reach_the_table() {
    let (client, _, store) = store();
    assert!(matches!(
        store.put_if_absent("", b"v", TTL).await,
        Err(StoreError::Invalid(_))
    ));
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
    assert!(matches!(store.get("").await, Err(StoreError::Invalid(_))));
    assert!(matches!(
        store
            .delete(&"k".repeat(oauthrelay_core::MAX_KEY_BYTES + 1))
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(client.calls(), 0);
}

#[tokio::test]
async fn client_failures_surface_as_backend_errors() {
    let (client, _, store) = store();
    client.failing.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.put_if_absent("k", b"v", TTL).await,
        Err(StoreError::Backend(_))
    ));
    assert!(matches!(store.get("k").await, Err(StoreError::Backend(_))));
    assert!(matches!(
        store.compare_and_swap("k", b"a", b"b", TTL).await,
        Err(StoreError::Backend(_))
    ));
    assert!(matches!(
        store.delete("k").await,
        Err(StoreError::Backend(_))
    ));
}
