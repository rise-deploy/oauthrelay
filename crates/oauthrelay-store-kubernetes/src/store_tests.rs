use super::*;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

const START: u64 = 1_800_000_000_000;
const TTL: Duration = Duration::from_secs(60);
const TTL_MS: u64 = 60_000;

type Objects = BTreeMap<String, Stored>;
type Interference = Arc<dyn Fn(&mut Objects) + Send + Sync>;

#[derive(Debug, Eq, PartialEq)]
enum Call {
    Get(String),
    Create(String),
    Replace(String, String),
    Delete(String, Option<String>),
    List {
        selector: String,
        limit: u32,
        token: Option<String>,
    },
}

/// Applies each operation exactly as its documentation states, and records every call.
#[derive(Default)]
struct FakeClient {
    objects: Mutex<Objects>,
    calls: Mutex<Vec<Call>>,
    versions: AtomicU64,
    /// Applies the next create or replace but reports it as a conflict, as a retry after a lost
    /// response does.
    lose_next_response: AtomicBool,
    failing: AtomicBool,
    /// Runs just before each `replace` takes effect: another writer getting in first.
    before_replace: Mutex<Option<Interference>>,
    /// Runs after each `list` has read its page, before the caller sees it.
    after_list: Mutex<Option<Interference>>,
    /// Caps the page size below the requested limit.
    max_page: Mutex<Option<usize>>,
    undecodable: Mutex<Vec<String>>,
    /// Makes the next `get` report the object as absent and remove it: it was deleted between
    /// the caller's previous request and this one.
    vanish_on_get: AtomicBool,
}

impl FakeClient {
    fn check_available(&self) -> anyhow::Result<()> {
        if self.failing.load(Ordering::SeqCst) {
            anyhow::bail!("api server unavailable");
        }
        Ok(())
    }

    fn next_version(&self) -> String {
        (self.versions.fetch_add(1, Ordering::SeqCst) + 1).to_string()
    }

    fn put_object(&self, name: &str, value: &[u8], expires_at_ms: u64) {
        let object = Stored {
            name: name.to_owned(),
            resource_version: self.next_version(),
            value: value.to_vec(),
            expires_at_ms,
        };
        self.objects.lock().unwrap().insert(name.to_owned(), object);
    }

    fn object(&self, key: &str) -> Option<Stored> {
        self.objects.lock().unwrap().get(&object_name(key)).cloned()
    }

    fn calls(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl KubernetesClient for FakeClient {
    fn target(&self) -> String {
        "fake.example in namespace \"test\"".into()
    }

    async fn get(&self, name: &str) -> anyhow::Result<Option<Stored>> {
        self.check_available()?;
        self.calls.lock().unwrap().push(Call::Get(name.to_owned()));
        if self.vanish_on_get.swap(false, Ordering::SeqCst) {
            self.objects.lock().unwrap().remove(name);
            return Ok(None);
        }
        Ok(self.objects.lock().unwrap().get(name).cloned())
    }

    async fn create(&self, record: NewRecord<'_>) -> anyhow::Result<CreateOutcome> {
        self.check_available()?;
        self.calls
            .lock()
            .unwrap()
            .push(Call::Create(record.name.to_owned()));
        if self.objects.lock().unwrap().contains_key(record.name) {
            return Ok(CreateOutcome::AlreadyExists);
        }
        self.put_object(record.name, record.value, record.expires_at_ms);
        if self.lose_next_response.swap(false, Ordering::SeqCst) {
            return Ok(CreateOutcome::AlreadyExists);
        }
        Ok(CreateOutcome::Created)
    }

    async fn replace(
        &self,
        record: NewRecord<'_>,
        resource_version: &str,
    ) -> anyhow::Result<ReplaceOutcome> {
        self.check_available()?;
        self.calls.lock().unwrap().push(Call::Replace(
            record.name.to_owned(),
            resource_version.to_owned(),
        ));
        let interference = self.before_replace.lock().unwrap().clone();
        if let Some(interference) = interference {
            interference(&mut self.objects.lock().unwrap());
        }
        let current = self.objects.lock().unwrap().get(record.name).cloned();
        match current {
            None => Ok(ReplaceOutcome::NotFound),
            Some(current) if current.resource_version != resource_version => {
                Ok(ReplaceOutcome::Conflict)
            }
            Some(_) => {
                self.put_object(record.name, record.value, record.expires_at_ms);
                if self.lose_next_response.swap(false, Ordering::SeqCst) {
                    return Ok(ReplaceOutcome::Conflict);
                }
                Ok(ReplaceOutcome::Replaced)
            }
        }
    }

    async fn delete(
        &self,
        name: &str,
        resource_version: Option<&str>,
    ) -> anyhow::Result<DeleteOutcome> {
        self.check_available()?;
        self.calls.lock().unwrap().push(Call::Delete(
            name.to_owned(),
            resource_version.map(str::to_owned),
        ));
        let mut objects = self.objects.lock().unwrap();
        match objects.get(name) {
            None => Ok(DeleteOutcome::NotFound),
            Some(current)
                if resource_version.is_some_and(|version| current.resource_version != version) =>
            {
                Ok(DeleteOutcome::Conflict)
            }
            Some(_) => {
                objects.remove(name);
                Ok(DeleteOutcome::Deleted)
            }
        }
    }

    async fn list(
        &self,
        label_selector: &str,
        limit: u32,
        continue_token: Option<&str>,
    ) -> anyhow::Result<Page> {
        self.check_available()?;
        self.calls.lock().unwrap().push(Call::List {
            selector: label_selector.to_owned(),
            limit,
            token: continue_token.map(str::to_owned),
        });
        let size = self
            .max_page
            .lock()
            .unwrap()
            .map_or(limit as usize, |cap| cap.min(limit as usize));
        // The token is the last name returned, so deletions between pages do not shift it.
        let objects = self.objects.lock().unwrap();
        let remaining: Vec<_> = objects
            .values()
            .filter(|object| continue_token.is_none_or(|token| object.name.as_str() > token))
            .cloned()
            .collect();
        let items: Vec<_> = remaining.iter().take(size).cloned().collect();
        drop(objects);
        let interference = self.after_list.lock().unwrap().clone();
        if let Some(interference) = interference {
            interference(&mut self.objects.lock().unwrap());
        }
        let continue_token = if items.len() < remaining.len() {
            items.last().map(|object| object.name.clone())
        } else {
            None
        };
        Ok(Page {
            items,
            undecodable: self.undecodable.lock().unwrap().clone(),
            continue_token,
        })
    }
}

fn store() -> (Arc<FakeClient>, Arc<AtomicU64>, KubernetesStore<FakeClient>) {
    let client = Arc::new(FakeClient::default());
    let now = Arc::new(AtomicU64::new(START));
    let source = now.clone();
    let store = KubernetesStore::with_clock(
        client.clone(),
        Arc::new(move || source.load(Ordering::SeqCst)),
    );
    (client, now, store)
}

fn interference(f: impl Fn(&mut Objects) + Send + Sync + 'static) -> Option<Interference> {
    Some(Arc::new(f))
}

/// Another writer replaces the record's value, which bumps its version.
fn overwrite(name: String, value: &'static [u8], expires_at_ms: u64) -> Interference {
    let versions = AtomicU64::new(1_000);
    Arc::new(move |objects: &mut Objects| {
        objects.insert(
            name.clone(),
            Stored {
                name: name.clone(),
                resource_version: format!("other-{}", versions.fetch_add(1, Ordering::SeqCst)),
                value: value.to_vec(),
                expires_at_ms,
            },
        );
    })
}

#[tokio::test]
async fn put_if_absent_creates_an_object_named_for_the_key() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    let name = object_name("replay:a");
    assert_eq!(client.calls(), vec![Call::Create(name.clone())]);
    let stored = client.object("replay:a").unwrap();
    assert_eq!(stored.name, name);
    assert_eq!(stored.value, b"1");
    assert_eq!(stored.expires_at_ms, START + TTL_MS);
}

#[tokio::test]
async fn put_if_absent_keeps_millisecond_precision() {
    let (client, _, store) = store();
    assert!(store
        .put_if_absent("replay:a", b"1", Duration::from_millis(1500))
        .await
        .unwrap());
    assert_eq!(
        client.object("replay:a").unwrap().expires_at_ms,
        START + 1500
    );
}

#[tokio::test]
async fn put_if_absent_leaves_a_live_record_alone() {
    let (client, _, store) = store();
    assert!(store
        .put_if_absent("replay:a", b"first", TTL)
        .await
        .unwrap());
    let before = client.object("replay:a").unwrap();
    client.calls();
    assert!(!store
        .put_if_absent("replay:a", b"second", TTL)
        .await
        .unwrap());
    assert_eq!(client.object("replay:a").unwrap(), before);
    let name = object_name("replay:a");
    assert_eq!(
        client.calls(),
        vec![Call::Create(name.clone()), Call::Get(name)]
    );
}

#[tokio::test]
async fn put_if_absent_takes_over_an_expired_record_with_its_resource_version() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"old", TTL).await.unwrap());
    let old = client.object("replay:a").unwrap();
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    client.calls();
    assert!(store.put_if_absent("replay:a", b"new", TTL).await.unwrap());
    let name = object_name("replay:a");
    assert_eq!(
        client.calls(),
        vec![
            Call::Create(name.clone()),
            Call::Get(name.clone()),
            Call::Replace(name, old.resource_version),
        ]
    );
    let stored = client.object("replay:a").unwrap();
    assert_eq!(stored.value, b"new");
    assert_eq!(stored.expires_at_ms, START + 2 * TTL_MS);
}

#[tokio::test]
async fn put_if_absent_reports_a_lost_create_response_as_success() {
    let (client, _, store) = store();
    client.lose_next_response.store(true, Ordering::SeqCst);
    assert!(store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    assert_eq!(client.object("replay:a").unwrap().value, b"mine");
}

#[tokio::test]
async fn put_if_absent_does_not_claim_another_writers_value_as_its_own() {
    let (client, _, store) = store();
    client.put_object(&object_name("replay:a"), b"theirs", START + TTL_MS);
    assert!(!store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
}

#[tokio::test]
async fn put_if_absent_does_not_claim_an_expired_copy_of_its_value() {
    let (client, _, store) = store();
    client.put_object(&object_name("replay:a"), b"mine", START);
    // The same bytes, but expired: the write is not ours and the record is replaced.
    assert!(store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    assert_eq!(
        client.object("replay:a").unwrap().expires_at_ms,
        START + TTL_MS
    );
}

#[tokio::test]
async fn put_if_absent_reports_a_lost_replace_response_as_success() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"old", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    client.lose_next_response.store(true, Ordering::SeqCst);
    assert!(store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    assert_eq!(client.object("replay:a").unwrap().value, b"mine");
}

#[tokio::test]
async fn put_if_absent_loses_a_race_to_replace_an_expired_record() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"old", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    // A concurrent writer takes the expired record first.
    *client.before_replace.lock().unwrap() = Some(overwrite(
        object_name("replay:a"),
        b"theirs",
        START + 2 * TTL_MS,
    ));
    assert!(!store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    assert_eq!(client.object("replay:a").unwrap().value, b"theirs");
}

#[tokio::test]
async fn put_if_absent_retries_a_conflicting_replace_a_bounded_number_of_times() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"old", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    // Every replace finds the record changed, yet it stays expired.
    *client.before_replace.lock().unwrap() =
        Some(overwrite(object_name("replay:a"), b"churn", START));
    client.calls();
    assert!(!store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    let replaces = client
        .calls()
        .into_iter()
        .filter(|call| matches!(call, Call::Replace(..)))
        .count();
    assert_eq!(replaces, 3);
}

#[tokio::test]
async fn put_if_absent_creates_again_when_the_object_vanishes_after_a_conflict() {
    let (client, _, store) = store();
    client.put_object(&object_name("replay:a"), b"theirs", START + TTL_MS);
    client.vanish_on_get.store(true, Ordering::SeqCst);
    assert!(store.put_if_absent("replay:a", b"mine", TTL).await.unwrap());
    assert_eq!(client.object("replay:a").unwrap().value, b"mine");
}

#[tokio::test]
async fn get_returns_live_records_with_their_remaining_ttl() {
    let (_, now, store) = store();
    assert_eq!(store.get("replay:a").await.unwrap(), None);
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    assert_eq!(
        store.get("replay:a").await.unwrap(),
        Some(Entry {
            value: b"1".to_vec(),
            expires_in: TTL
        })
    );
    now.fetch_add(45_250, Ordering::SeqCst);
    assert_eq!(
        store.get("replay:a").await.unwrap().unwrap().expires_in,
        Duration::from_millis(TTL_MS - 45_250)
    );
}

#[tokio::test]
async fn get_judges_expiry_by_the_clock_not_by_deletion() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    now.store(START + TTL_MS - 1, Ordering::SeqCst);
    assert!(store.get("replay:a").await.unwrap().is_some());
    now.store(START + TTL_MS, Ordering::SeqCst);
    assert_eq!(store.get("replay:a").await.unwrap(), None);
    // The expired object is still in the cluster; it only reads as absent.
    assert!(client.object("replay:a").is_some());
}

#[tokio::test]
async fn compare_and_swap_replaces_a_matching_record_with_the_version_it_read() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("refresh:a", b"one", TTL).await.unwrap());
    let before = client.object("refresh:a").unwrap();
    now.fetch_add(10_000, Ordering::SeqCst);
    client.calls();
    assert!(store
        .compare_and_swap("refresh:a", b"one", b"two", Duration::from_secs(120))
        .await
        .unwrap());
    let name = object_name("refresh:a");
    assert_eq!(
        client.calls(),
        vec![
            Call::Get(name.clone()),
            Call::Replace(name, before.resource_version.clone())
        ]
    );
    let after = client.object("refresh:a").unwrap();
    assert_eq!(after.value, b"two");
    assert_eq!(after.expires_at_ms, START + 10_000 + 120_000);
    assert_ne!(after.resource_version, before.resource_version);
}

#[tokio::test]
async fn compare_and_swap_does_not_write_without_a_live_matching_record() {
    let (client, now, store) = store();
    assert!(!store
        .compare_and_swap("refresh:a", b"one", b"two", TTL)
        .await
        .unwrap());
    assert!(store.put_if_absent("refresh:a", b"one", TTL).await.unwrap());
    assert!(!store
        .compare_and_swap("refresh:a", b"other", b"two", TTL)
        .await
        .unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    assert!(!store
        .compare_and_swap("refresh:a", b"one", b"two", TTL)
        .await
        .unwrap());
    assert!(!client
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Replace(..))));
    assert_eq!(client.object("refresh:a").unwrap().value, b"one");
}

#[tokio::test]
async fn compare_and_swap_loses_to_a_concurrent_writer() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("refresh:a", b"one", TTL).await.unwrap());
    *client.before_replace.lock().unwrap() = Some(overwrite(
        object_name("refresh:a"),
        b"theirs",
        START + TTL_MS,
    ));
    assert!(!store
        .compare_and_swap("refresh:a", b"one", b"mine", TTL)
        .await
        .unwrap());
    assert_eq!(client.object("refresh:a").unwrap().value, b"theirs");
}

#[tokio::test]
async fn compare_and_swap_reports_a_lost_response_as_success() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("refresh:a", b"one", TTL).await.unwrap());
    client.lose_next_response.store(true, Ordering::SeqCst);
    assert!(store
        .compare_and_swap("refresh:a", b"one", b"mine", TTL)
        .await
        .unwrap());
    assert_eq!(client.object("refresh:a").unwrap().value, b"mine");
}

#[tokio::test]
async fn compare_and_swap_fails_when_the_record_disappears() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("refresh:a", b"one", TTL).await.unwrap());
    // Deleted after the read: the replace finds no object.
    *client.before_replace.lock().unwrap() = interference(|objects| objects.clear());
    assert!(!store
        .compare_and_swap("refresh:a", b"one", b"mine", TTL)
        .await
        .unwrap());
    assert!(client.object("refresh:a").is_none());
}

#[tokio::test]
async fn compare_and_swap_exactly_one_of_concurrent_callers_wins() {
    let (client, _, store) = store();
    let store = Arc::new(store);
    assert!(store
        .put_if_absent("refresh:a", b"start", TTL)
        .await
        .unwrap());
    let mut tasks = Vec::new();
    for index in 0..20 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let new = format!("writer-{index}");
            store
                .compare_and_swap("refresh:a", b"start", new.as_bytes(), TTL)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    assert!(client
        .object("refresh:a")
        .unwrap()
        .value
        .starts_with(b"writer-"));
}

#[tokio::test]
async fn delete_removes_the_object_unconditionally_and_tolerates_absence() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    client.calls();
    store.delete("replay:a").await.unwrap();
    store.delete("replay:a").await.unwrap();
    let name = object_name("replay:a");
    assert_eq!(
        client.calls(),
        vec![Call::Delete(name.clone(), None), Call::Delete(name, None)]
    );
    assert!(client.object("replay:a").is_none());
    assert!(store.put_if_absent("replay:a", b"2", TTL).await.unwrap());
}

#[tokio::test]
async fn invalid_requests_never_reach_the_api_server() {
    let (client, _, store) = store();
    let long = "k".repeat(oauthrelay_core::MAX_KEY_BYTES + 1);
    assert!(matches!(
        store.put_if_absent("", b"1", TTL).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.put_if_absent(&long, b"1", TTL).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.put_if_absent("replay:a", b"1", Duration::ZERO).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.put_if_absent("replay:a", b"1", Duration::MAX).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store
            .compare_and_swap("replay:a", b"1", b"2", Duration::MAX)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(store.get("").await, Err(StoreError::Invalid(_))));
    assert!(matches!(
        store.compare_and_swap("", b"1", b"2", TTL).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.delete("").await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(client.call_count(), 0);
}

#[tokio::test]
async fn backend_failures_surface_as_backend_errors() {
    let (client, _, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    client.failing.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.put_if_absent("replay:b", b"1", TTL).await,
        Err(StoreError::Backend(_))
    ));
    assert!(matches!(
        store.get("replay:a").await,
        Err(StoreError::Backend(_))
    ));
    assert!(matches!(
        store.compare_and_swap("replay:a", b"1", b"2", TTL).await,
        Err(StoreError::Backend(_))
    ));
    assert!(matches!(
        store.delete("replay:a").await,
        Err(StoreError::Backend(_))
    ));
}

#[test]
fn object_names_are_stable_dns_labels_that_cannot_collide_with_dex() {
    let name = object_name("replay:code:abc");
    assert_eq!(name, object_name("replay:code:abc"));
    assert_ne!(name, object_name("replay:code:abd"));
    assert_eq!(name.len(), 63);
    assert!(name.starts_with(NAME_PREFIX));
    assert!(name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
    // Dex names its objects with unpadded lowercase base32 and no hyphen: a name that contains
    // one is never a Dex name.
    assert!(name.contains('-'));
    // The longest key still yields a valid name.
    assert_eq!(
        object_name(&"k".repeat(oauthrelay_core::MAX_KEY_BYTES)).len(),
        63
    );
}

#[test]
fn base32_matches_rfc_4648_vectors() {
    use crate::mapping::base32_lower;
    for (input, expected) in [
        ("", ""),
        ("f", "my"),
        ("fo", "mzxq"),
        ("foo", "mzxw6"),
        ("foob", "mzxw6yq"),
        ("fooba", "mzxw6ytb"),
        ("foobar", "mzxw6ytboi"),
    ] {
        assert_eq!(base32_lower(input.as_bytes()), expected, "{input:?}");
    }
}

#[tokio::test]
async fn sweep_deletes_expired_objects_with_a_version_precondition() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:old", b"1", TTL).await.unwrap());
    now.fetch_add(30_000, Ordering::SeqCst);
    assert!(store.put_if_absent("replay:new", b"1", TTL).await.unwrap());
    now.fetch_add(30_000, Ordering::SeqCst);
    let old = client.object("replay:old").unwrap();
    client.calls();
    assert_eq!(
        store.sweep().await.unwrap(),
        SweepReport {
            listed: 2,
            deleted: 1,
            skipped: 0
        }
    );
    assert!(client.object("replay:old").is_none());
    assert!(client.object("replay:new").is_some());
    assert_eq!(
        client.calls(),
        vec![
            Call::List {
                selector: MANAGED_SELECTOR.into(),
                limit: SWEEP_PAGE_SIZE,
                token: None
            },
            Call::Delete(old.name, Some(old.resource_version)),
        ]
    );
}

#[tokio::test]
async fn sweep_spares_a_record_renewed_between_the_list_and_the_delete() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("refresh:a", b"1", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    // Another replica takes the expired record over just after this sweep listed it.
    *client.after_list.lock().unwrap() = Some(overwrite(
        object_name("refresh:a"),
        b"renewed",
        START + 2 * TTL_MS,
    ));
    assert_eq!(
        store.sweep().await.unwrap(),
        SweepReport {
            listed: 1,
            deleted: 0,
            skipped: 1
        }
    );
    assert_eq!(client.object("refresh:a").unwrap().value, b"renewed");
}

#[tokio::test]
async fn sweep_tolerates_objects_deleted_by_another_replica() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    *client.after_list.lock().unwrap() = interference(|objects| objects.clear());
    assert_eq!(
        store.sweep().await.unwrap(),
        SweepReport {
            listed: 1,
            deleted: 0,
            skipped: 1
        }
    );
}

#[tokio::test]
async fn sweep_pages_through_every_object_and_always_selects_managed_ones() {
    let (client, now, store) = store();
    for index in 0..5 {
        assert!(store
            .put_if_absent(&format!("replay:{index}"), b"1", TTL)
            .await
            .unwrap());
    }
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    *client.max_page.lock().unwrap() = Some(2);
    client.calls();
    assert_eq!(store.sweep().await.unwrap().deleted, 5);
    assert!(client.objects.lock().unwrap().is_empty());
    let lists: Vec<_> = client
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::List {
                selector, token, ..
            } => Some((selector, token)),
            _ => None,
        })
        .collect();
    assert_eq!(lists.len(), 3);
    assert!(lists
        .iter()
        .all(|(selector, _)| selector == MANAGED_SELECTOR));
    // Each page resumes where the previous one ended.
    assert_eq!(lists[0].1, None);
    assert!(lists[1].1.is_some() && lists[2].1.is_some() && lists[1].1 != lists[2].1);
}

#[tokio::test]
async fn sweep_reports_objects_it_cannot_decode_and_carries_on() {
    let (client, now, store) = store();
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    client
        .undecodable
        .lock()
        .unwrap()
        .push("oauthrelay-broken".into());
    assert_eq!(store.sweep().await.unwrap().deleted, 1);
}

#[tokio::test]
async fn sweep_failures_are_errors() {
    let (client, _, store) = store();
    client.failing.store(true, Ordering::SeqCst);
    assert!(store.sweep().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn the_sweeper_runs_on_its_interval_and_stops_with_the_store() {
    let client = Arc::new(FakeClient::default());
    let now = Arc::new(AtomicU64::new(START));
    let source = now.clone();
    let store = KubernetesStore::with_clock(
        client.clone(),
        Arc::new(move || source.load(Ordering::SeqCst)),
    )
    .with_sweeper(Duration::from_secs(60));
    assert!(store.put_if_absent("replay:a", b"1", TTL).await.unwrap());
    now.fetch_add(TTL_MS, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(
        client.object("replay:a").is_some(),
        "not before the first interval"
    );
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(client.object("replay:a").is_none());

    drop(store);
    client.calls();
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert_eq!(
        client.call_count(),
        0,
        "the sweeper stops when the store is dropped"
    );
}

#[tokio::test]
async fn probe_lists_one_managed_object_and_explains_failures() {
    let (client, _, store) = store();
    store.probe().await.unwrap();
    assert_eq!(
        client.calls(),
        vec![Call::List {
            selector: MANAGED_SELECTOR.into(),
            limit: 1,
            token: None
        }]
    );
    client.failing.store(true, Ordering::SeqCst);
    let error = format!("{:#}", store.probe().await.unwrap_err());
    assert!(
        error.contains("fake.example in namespace \"test\""),
        "{error}"
    );
    assert!(error.contains("api server unavailable"), "{error}");
}

#[test]
fn labels_mark_managed_objects_and_carry_the_purpose() {
    use crate::mapping::labels;
    let managed = (MANAGED_BY_LABEL.to_owned(), MANAGED_BY_VALUE.to_owned());
    assert_eq!(
        MANAGED_SELECTOR,
        format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}")
    );
    let purposes: HashMap<_, _> = [
        ("replay:code:abc", Some("replay")),
        ("refresh:handle:abc", Some("refresh")),
        ("plain", Some("plain")),
        ("with-dash_and.dot:x", Some("with-dash_and.dot")),
        (":leading", None),
        ("-bad:x", None),
        ("bad-:x", None),
        ("has space:x", None),
        ("ünï:x", None),
    ]
    .into_iter()
    .collect();
    for (key, purpose) in purposes {
        let labels = labels(key);
        assert_eq!(labels.get(&managed.0), Some(&managed.1), "{key}");
        assert_eq!(
            labels.get(PURPOSE_LABEL).map(String::as_str),
            purpose,
            "{key}"
        );
    }
    assert!(!labels(&"p".repeat(64)).contains_key(PURPOSE_LABEL));
    assert!(labels(&"p".repeat(63)).contains_key(PURPOSE_LABEL));
}
