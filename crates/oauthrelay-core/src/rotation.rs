//! Rotating refresh-token handles (`rrt2.`).
//!
//! In `rotating` mode a relay hands its client an opaque, random handle in place of the upstream
//! refresh token. Each handle is single use: presenting it refreshes upstream and returns a
//! successor handle. The state that makes this safe lives in the [`TransientStore`].
//!
//! # Store layout
//!
//! Keys never contain a handle or a family id, only a SHA-256 over the relay key and that value,
//! so the store cannot be used to recover or forge a handle:
//!
//! | Key | Value | TTL |
//! | --- | --- | --- |
//! | `refresh:handle:{hash(handle)}` | the handle's [`Record`] | until the family expires |
//! | `refresh:grace:{hash(handle, claim id)}` | the token response returned for that rotation | grace period plus a margin |
//! | `refresh:revoked:{hash(family id)}` | `1`, present when the family is revoked | until the family expires |
//! | `refresh:head:{hash(family id)}` | the store key of the family's newest handle record (not secret) | until the family expires |
//!
//! The head pointer lets a revocation find and delete the one record that still holds an upstream
//! token without walking the family's history; each `Rotated` tombstone also names its
//! successor, so a stale pointer is repaired by following the chain.
//!
//! Record and response values are sealed with the relay's [`Sealer`]. The associated data binds
//! the relay key, the purpose, and the store key, so the store never holds a plaintext token and a
//! value cannot be moved to another key or relay.
//!
//! A [`Record`] is `Active` (refreshable), `Claimed` (one caller is refreshing upstream), or
//! `Rotated` (a successor exists). A rotated record is a tombstone without any token that remains
//! until the family expires, so a replay is recognized for the family's whole life. Its response
//! is stored separately and disappears with the grace period, so access tokens are not kept
//! around longer than the grace window needs.
//!
//! Every state change is a compare-and-swap against the exact bytes last read. Sealing uses a
//! random nonce, so two writes never produce equal bytes and a stale writer cannot match a value
//! written by someone else.

use crate::{
    refresh_handle::{
        names_refresh_token, open_handle, upstream_refresh_token, with_refresh_token, HandleError,
        HANDLE_PREFIX,
    },
    router::StoredResponse,
    RefreshTokens, ResourceKey, SealError, Sealer, StoreError, TransientStore,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

/// Prefix of every rotating handle.
pub(crate) const ROTATING_PREFIX: &str = "rrt2.";
const HANDLE_BYTES: usize = 32;
const HANDLE_KEY_PREFIX: &str = "refresh:handle:";
const GRACE_KEY_PREFIX: &str = "refresh:grace:";
const REVOKED_KEY_PREFIX: &str = "refresh:revoked:";
const HEAD_KEY_PREFIX: &str = "refresh:head:";
/// Longest chain of rotated records followed when erasing a revoked family. The head pointer
/// makes the walk one or two hops; the bound only limits the damage of a stale pointer.
const MAX_ERASE_HOPS: usize = 1_000;
const RECORD_PURPOSE: &str = "refresh-record";
const GRACE_PURPOSE: &str = "refresh-grace";
/// How long a recorded response outlives the grace period, so a request that arrives right at
/// the boundary still finds it.
const GRACE_RESPONSE_MARGIN: Duration = Duration::from_secs(10);

/// Unix time in milliseconds.
pub(crate) type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub(crate) fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or_default()
    })
}

/// Waiting and lease durations of the claim protocol.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    /// Pause between polls while another caller holds the claim.
    pub poll_interval: Duration,
    /// How long a caller waits for the claim holder before answering `temporarily_unavailable`.
    pub resolve_wait: Duration,
    /// How long the upstream refresh may take before it is abandoned and the claim released.
    pub upstream_timeout: Duration,
    /// Age after which a claim is presumed abandoned (its holder crashed or was suspended) and
    /// the handle can be claimed again. It must exceed `upstream_timeout`.
    pub claim_lease: Duration,
    /// How long a single seal or unseal may take before it fails as unavailable. A claim holder
    /// seals once to take the claim and three times to commit, around the upstream refresh, and
    /// must finish before the lease ends or another caller takes the claim over and replays the
    /// upstream token. So `upstream_timeout + 4 * sealer_timeout` must stay below `claim_lease`.
    pub sealer_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            resolve_wait: Duration::from_secs(5),
            upstream_timeout: Duration::from_secs(30),
            claim_lease: Duration::from_secs(60),
            sealer_timeout: Duration::from_secs(5),
        }
    }
}

/// Why the upstream could not be asked or did not answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpstreamFailure {
    /// The endpoints could not be resolved; the router answers with this bare status.
    Status(u16),
    /// The request failed or its response could not be read.
    Request,
}

/// Performs the upstream refresh grant. Implemented by the router; faked in tests.
#[async_trait]
pub(crate) trait UpstreamRefresher: Send + Sync {
    async fn refresh(&self, upstream_token: &str) -> Result<StoredResponse, UpstreamFailure>;
}

/// Why a code-grant response could not be given a handle. Neither case returns the response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IssueError {
    /// The store failed.
    Store,
    /// The sealer could not be reached.
    SealerUnavailable,
    /// A 2xx body that is not a JSON object yet carries a refresh token.
    UnrecognizedBody,
}

/// What the router should answer.
#[derive(Debug)]
pub(crate) enum RefreshOutcome {
    /// Return this response unchanged: a rotation, a replay answered within the grace period, or
    /// an upstream error passed through.
    Response(StoredResponse),
    /// `invalid_grant`: unknown, expired, revoked, or reused handle.
    InvalidGrant,
    /// Another caller holds the claim and did not finish in time; retry.
    Unavailable,
    /// The upstream could not be reached.
    UpstreamFailed(UpstreamFailure),
    /// The upstream answered success with something that is not a JSON token response.
    UpstreamUnusable,
    /// The store failed. The request fails closed.
    StoreFailed,
    /// The sealer could not be reached. The request fails closed; the stored state is untouched.
    SealerUnavailable,
}

#[derive(Debug, thiserror::Error)]
enum Fault {
    #[error("{0}")]
    Store(#[from] StoreError),
    /// A stored value failed to open or encode: tampered, written for another key, or sealed with
    /// a key that is no longer configured.
    #[error("a stored refresh-token value could not be sealed or opened")]
    Sealing,
    /// The sealer could not be reached, so nothing is known about the value. Unlike `Sealing`,
    /// this is never evidence of tampering and never causes a record to be discarded.
    #[error("the sealer is unavailable")]
    SealerUnavailable,
    /// A create-only write found a record that a random key cannot have.
    #[error("a refresh-token record that must be new already exists")]
    Conflict,
}

impl Fault {
    fn from_seal_error(error: SealError) -> Self {
        match error {
            SealError::Unavailable => Self::SealerUnavailable,
            SealError::InvalidKey | SealError::InvalidEnvelope => Self::Sealing,
        }
    }
}

type Result<T, E = Fault> = std::result::Result<T, E>;

#[derive(Serialize, Deserialize)]
struct Record {
    family_id: [u8; 16],
    /// Unix milliseconds at which the family stops being refreshable.
    family_expires_ms: u64,
    state: State,
}

#[derive(Serialize, Deserialize)]
enum State {
    Active {
        upstream_token: String,
    },
    Claimed {
        upstream_token: String,
        claim_id: [u8; 16],
        claimed_ms: u64,
    },
    Rotated {
        rotated_ms: u64,
        claim_id: [u8; 16],
        /// Store key of the successor's record.
        successor_key: String,
    },
}

/// A record together with the exact bytes it was read as, which is what compare-and-swap needs.
struct Loaded {
    bytes: Vec<u8>,
    record: Record,
}

/// A claim this caller holds.
struct Claim {
    bytes: Vec<u8>,
    claim_id: [u8; 16],
    upstream_token: String,
    family_id: [u8; 16],
    family_expires_ms: u64,
}

/// Rotation state machine for one relay.
pub(crate) struct Rotator {
    store: Arc<dyn TransientStore>,
    sealer: Arc<dyn Sealer>,
    relay: ResourceKey,
    grace: Duration,
    max_lifetime: Duration,
    clock: Clock,
    timing: Timing,
}

impl Rotator {
    pub(crate) fn new(
        store: Arc<dyn TransientStore>,
        sealer: Arc<dyn Sealer>,
        relay: ResourceKey,
        settings: &RefreshTokens,
    ) -> Self {
        Self {
            store,
            sealer,
            relay,
            grace: Duration::from_secs(settings.grace_period_seconds),
            max_lifetime: Duration::from_secs(settings.max_lifetime_seconds),
            clock: system_clock(),
            timing: Timing::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    /// Starts a family for the upstream token of a code grant and returns its first handle, or
    /// `Err` when the store failed (the caller must not return the upstream token).
    pub(crate) async fn issue(&self, upstream_token: &str) -> Result<String, IssueError> {
        let handle = new_handle();
        let created = self.create_family(&handle, upstream_token).await;
        created.map(|()| handle).map_err(|fault| {
            self.log_fault(&fault);
            match fault {
                Fault::SealerUnavailable => IssueError::SealerUnavailable,
                _ => IssueError::Store,
            }
        })
    }

    /// Replaces the `refresh_token` of a successful code-grant response with a new family's first
    /// handle. `Ok(None)` means the response has no refresh token and passes unchanged. Like the
    /// `sealed` mode, a 2xx body that is not a JSON object but names a `refresh_token` is refused
    /// rather than returned.
    pub(crate) async fn issue_in_response(
        &self,
        response: &StoredResponse,
    ) -> Result<Option<Vec<u8>>, IssueError> {
        let Some(token) = upstream_refresh_token(response.status, &response.body) else {
            return if is_success(response)
                && serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(
                    &response.body,
                )
                .is_err()
                && names_refresh_token(&response.body)
            {
                Err(IssueError::UnrecognizedBody)
            } else {
                Ok(None)
            };
        };
        let handle = self.issue(&token).await?;
        with_refresh_token(response.status, &response.body, &handle)
            .map(Some)
            .ok_or(IssueError::UnrecognizedBody)
    }

    /// Runs a refresh grant for `presented`.
    pub(crate) async fn refresh(
        &self,
        presented: &str,
        upstream: &dyn UpstreamRefresher,
    ) -> RefreshOutcome {
        let result = if presented.starts_with(HANDLE_PREFIX) {
            self.refresh_sealed_handle(presented, upstream).await
        } else if valid_handle_shape(presented) {
            self.refresh_rotating(presented, upstream).await
        } else {
            Ok(RefreshOutcome::InvalidGrant)
        };
        result.unwrap_or_else(|fault| {
            self.log_fault(&fault);
            match fault {
                // The record exists but this relay cannot open it (seal key replaced, or the
                // value was tampered with). Retrying cannot help, so the client signs in again.
                Fault::Sealing => RefreshOutcome::InvalidGrant,
                // The key service did not answer; the record may be perfectly good.
                Fault::SealerUnavailable => RefreshOutcome::SealerUnavailable,
                Fault::Store(_) | Fault::Conflict => RefreshOutcome::StoreFailed,
            }
        })
    }

    /// Accepts a `sealed` handle from before the relay switched to `rotating` and starts a new
    /// family from it. The sealed handle is stateless, so it cannot be claimed or revoked.
    async fn refresh_sealed_handle(
        &self,
        presented: &str,
        upstream: &dyn UpstreamRefresher,
    ) -> Result<RefreshOutcome> {
        let opened = match tokio::time::timeout(
            self.timing.sealer_timeout,
            open_handle(self.sealer.as_ref(), &self.relay, presented),
        )
        .await
        {
            Ok(Ok(opened)) => opened,
            Ok(Err(HandleError::Invalid)) => return Ok(RefreshOutcome::InvalidGrant),
            Ok(Err(HandleError::SealerUnavailable)) | Err(_) => {
                return Err(Fault::SealerUnavailable)
            }
        };
        // The sealed handle records when it was issued. Past the maximum lifetime it no longer
        // earns a family: the user signs in again.
        let issued_ms = opened.issued_at.saturating_mul(1000);
        if (self.clock)() >= issued_ms.saturating_add(self.max_lifetime.as_millis() as u64) {
            return Ok(RefreshOutcome::InvalidGrant);
        }
        let response = match self.ask_upstream(upstream, &opened.upstream_token).await {
            Ok(response) => response,
            Err(failure) => return Ok(RefreshOutcome::UpstreamFailed(failure)),
        };
        if is_invalid_grant(&response) {
            return Ok(RefreshOutcome::Response(response));
        }
        if !is_success(&response) {
            return Ok(RefreshOutcome::Response(response));
        }
        let successor_token = upstream_refresh_token(response.status, &response.body)
            .unwrap_or(opened.upstream_token);
        let handle = new_handle();
        let Some(body) = with_refresh_token(response.status, &response.body, &handle) else {
            return Ok(RefreshOutcome::UpstreamUnusable);
        };
        self.create_family(&handle, &successor_token).await?;
        tracing::info!(
            target: "oauthrelay::refresh",
            relay = %self.relay,
            outcome = "migrated_sealed_handle",
            "sealed refresh token migrated to a rotating family"
        );
        Ok(RefreshOutcome::Response(StoredResponse {
            body,
            ..response
        }))
    }

    async fn refresh_rotating(
        &self,
        presented: &str,
        upstream: &dyn UpstreamRefresher,
    ) -> Result<RefreshOutcome> {
        let handle_key = self.handle_key(presented);
        let started = tokio::time::Instant::now();
        loop {
            let Some(loaded) = self.load(&handle_key).await? else {
                return Ok(RefreshOutcome::InvalidGrant);
            };
            let now = (self.clock)();
            if now >= loaded.record.family_expires_ms {
                return Ok(RefreshOutcome::InvalidGrant);
            }
            if self.is_revoked(&loaded.record.family_id).await? {
                return Ok(RefreshOutcome::InvalidGrant);
            }
            match &loaded.record.state {
                State::Active { upstream_token } => {
                    if let Some(claim) = self.claim(&handle_key, &loaded, upstream_token).await? {
                        return self.perform(&handle_key, claim, upstream).await;
                    }
                }
                State::Claimed {
                    upstream_token,
                    claimed_ms,
                    ..
                } => {
                    let lease_ms = self.timing.claim_lease.as_millis() as u64;
                    if now.saturating_sub(*claimed_ms) > lease_ms {
                        tracing::warn!(
                            target: "oauthrelay::refresh",
                            relay = %self.relay,
                            family = %self.family_label(&loaded.record.family_id),
                            "taking over an abandoned refresh claim"
                        );
                        if let Some(claim) =
                            self.claim(&handle_key, &loaded, upstream_token).await?
                        {
                            return self.perform(&handle_key, claim, upstream).await;
                        }
                    }
                }
                State::Rotated {
                    rotated_ms,
                    claim_id,
                    ..
                } => {
                    let within_grace =
                        now.saturating_sub(*rotated_ms) <= self.grace.as_millis() as u64;
                    if !within_grace {
                        return self.reuse_detected(&handle_key, &loaded.record).await;
                    }
                    let grace_key = self.grace_key(&handle_key, claim_id);
                    if let Some(response) = self.load_grace_response(&grace_key).await? {
                        tracing::info!(
                            target: "oauthrelay::refresh",
                            relay = %self.relay,
                            family = %self.family_label(&loaded.record.family_id),
                            outcome = "replayed_within_grace",
                            "refresh answered with the recorded successor"
                        );
                        return Ok(RefreshOutcome::Response(response));
                    }
                }
            }
            if started.elapsed() >= self.timing.resolve_wait {
                return Ok(RefreshOutcome::Unavailable);
            }
            tokio::time::sleep(self.timing.poll_interval).await;
        }
    }

    /// Tries to take the claim. `None` means someone else changed the record first.
    async fn claim(
        &self,
        handle_key: &str,
        loaded: &Loaded,
        upstream_token: &str,
    ) -> Result<Option<Claim>> {
        let now = (self.clock)();
        let Some(ttl) = ttl_until(loaded.record.family_expires_ms, now) else {
            return Ok(None);
        };
        let claim_id = random_array::<16>();
        let bytes = self
            .seal(
                RECORD_PURPOSE,
                handle_key,
                &Record {
                    family_id: loaded.record.family_id,
                    family_expires_ms: loaded.record.family_expires_ms,
                    state: State::Claimed {
                        upstream_token: upstream_token.to_owned(),
                        claim_id,
                        claimed_ms: now,
                    },
                },
            )
            .await?;
        let won = self
            .store
            .compare_and_swap(handle_key, &loaded.bytes, &bytes, ttl)
            .await?;
        Ok(won.then(|| Claim {
            bytes,
            claim_id,
            upstream_token: upstream_token.to_owned(),
            family_id: loaded.record.family_id,
            family_expires_ms: loaded.record.family_expires_ms,
        }))
    }

    /// Refreshes upstream as the claim holder and records the outcome.
    async fn perform(
        &self,
        handle_key: &str,
        claim: Claim,
        upstream: &dyn UpstreamRefresher,
    ) -> Result<RefreshOutcome> {
        let family = self.family_label(&claim.family_id);
        let response = match self.ask_upstream(upstream, &claim.upstream_token).await {
            Ok(response) => response,
            Err(failure) => {
                self.release(handle_key, &claim).await;
                tracing::warn!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    %family,
                    outcome = "upstream_unreachable",
                    "refresh claim released"
                );
                return Ok(RefreshOutcome::UpstreamFailed(failure));
            }
        };
        if is_invalid_grant(&response) {
            // The upstream no longer honours this family's token, so no member can succeed.
            self.revoke(&claim.family_id, claim.family_expires_ms, handle_key)
                .await?;
            tracing::warn!(
                target: "oauthrelay::refresh",
                relay = %self.relay,
                %family,
                outcome = "upstream_invalid_grant",
                "family revoked"
            );
            return Ok(RefreshOutcome::Response(response));
        }
        if !is_success(&response) {
            self.release(handle_key, &claim).await;
            tracing::warn!(
                target: "oauthrelay::refresh",
                relay = %self.relay,
                %family,
                upstream_status = response.status,
                outcome = "upstream_error",
                "refresh claim released"
            );
            return Ok(RefreshOutcome::Response(response));
        }
        let rotated_upstream = upstream_refresh_token(response.status, &response.body);
        let upstream_rotated = rotated_upstream.is_some();
        let successor_token = rotated_upstream.unwrap_or_else(|| claim.upstream_token.clone());
        let successor_handle = new_handle();
        let Some(body) = with_refresh_token(response.status, &response.body, &successor_handle)
        else {
            self.release(handle_key, &claim).await;
            tracing::warn!(
                target: "oauthrelay::refresh",
                relay = %self.relay,
                %family,
                outcome = "upstream_response_unusable",
                "refresh claim released"
            );
            return Ok(RefreshOutcome::UpstreamUnusable);
        };
        let response = StoredResponse { body, ..response };
        match self
            .commit(
                handle_key,
                &claim,
                &successor_handle,
                &successor_token,
                &response,
            )
            .await
        {
            Ok(Commit::Rotated) if self.is_revoked(&claim.family_id).await? => {
                // The family was revoked while this refresh was in flight. The revocation could
                // not see the successor yet, so remove what this refresh created.
                let grace_key = self.grace_key(handle_key, &claim.claim_id);
                self.discard(&[&grace_key, &self.handle_key(&successor_handle)])
                    .await;
                tracing::warn!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    %family,
                    outcome = "revoked_in_flight",
                    "family was revoked while a refresh was in flight; tokens withheld"
                );
                Ok(RefreshOutcome::InvalidGrant)
            }
            Ok(Commit::Rotated) => {
                tracing::info!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    %family,
                    upstream_rotated,
                    outcome = "rotated",
                    "refresh token rotated"
                );
                Ok(RefreshOutcome::Response(response))
            }
            Ok(Commit::Lost) if self.is_revoked(&claim.family_id).await? => {
                // The revocation deleted the claimed record this refresh was about to rotate.
                Ok(RefreshOutcome::InvalidGrant)
            }
            Ok(Commit::Lost) => {
                tracing::warn!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    %family,
                    outcome = "claim_lost",
                    "refresh claim was taken over before the successor was recorded"
                );
                Ok(RefreshOutcome::Unavailable)
            }
            Err(fault) => Err(fault),
        }
    }

    /// Records the successor and flips the handle to `Rotated`.
    ///
    /// The response and the successor are written before the handle changes state, so a record
    /// that reads `Rotated` always has both. A failure before the final swap removes what was
    /// written and releases the claim. A failed swap (outcome unknown) leaves everything: if it
    /// did apply the handle is rotated and complete, and if it did not the claim lease expires.
    async fn commit(
        &self,
        handle_key: &str,
        claim: &Claim,
        successor_handle: &str,
        successor_token: &str,
        response: &StoredResponse,
    ) -> Result<Commit> {
        let now = (self.clock)();
        let Some(family_ttl) = ttl_until(claim.family_expires_ms, now) else {
            return Ok(Commit::Lost);
        };
        let grace_key = self.grace_key(handle_key, &claim.claim_id);
        let successor_key = self.handle_key(successor_handle);
        let grace_ttl = (self.grace + GRACE_RESPONSE_MARGIN).min(family_ttl);
        let prepared = async {
            let sealed_response = self.seal(GRACE_PURPOSE, &grace_key, response).await?;
            if !self
                .store
                .put_if_absent(&grace_key, &sealed_response, grace_ttl)
                .await?
            {
                return Err(Fault::Conflict);
            }
            let successor = self
                .seal(
                    RECORD_PURPOSE,
                    &successor_key,
                    &Record {
                        family_id: claim.family_id,
                        family_expires_ms: claim.family_expires_ms,
                        state: State::Active {
                            upstream_token: successor_token.to_owned(),
                        },
                    },
                )
                .await?;
            if !self
                .store
                .put_if_absent(&successor_key, &successor, family_ttl)
                .await?
            {
                return Err(Fault::Conflict);
            }
            self.seal(
                RECORD_PURPOSE,
                handle_key,
                &Record {
                    family_id: claim.family_id,
                    family_expires_ms: claim.family_expires_ms,
                    state: State::Rotated {
                        rotated_ms: now,
                        claim_id: claim.claim_id,
                        successor_key: successor_key.clone(),
                    },
                },
            )
            .await
        }
        .await;
        let rotated = match prepared {
            Ok(rotated) => rotated,
            Err(fault) => {
                self.discard(&[&grace_key, &successor_key]).await;
                self.release(handle_key, claim).await;
                return Err(fault);
            }
        };
        let swapped = self
            .store
            .compare_and_swap(handle_key, &claim.bytes, &rotated, family_ttl)
            .await?;
        if swapped {
            // The head pointer is an accelerator: if this fails the next revocation follows the
            // chain from the old head, so the rotation still stands.
            let moved = self
                .store
                .compare_and_swap(
                    &self.head_key(&claim.family_id),
                    handle_key.as_bytes(),
                    successor_key.as_bytes(),
                    family_ttl,
                )
                .await;
            if !matches!(moved, Ok(true)) {
                tracing::warn!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    family = %self.family_label(&claim.family_id),
                    "family head pointer was not advanced"
                );
            }
            Ok(Commit::Rotated)
        } else {
            self.discard(&[&grace_key, &successor_key]).await;
            Ok(Commit::Lost)
        }
    }

    /// Hands the claim back so the handle can be presented again. Best effort: if it fails the
    /// claim lease expires on its own.
    async fn release(&self, handle_key: &str, claim: &Claim) {
        let released = self
            .seal(
                RECORD_PURPOSE,
                handle_key,
                &Record {
                    family_id: claim.family_id,
                    family_expires_ms: claim.family_expires_ms,
                    state: State::Active {
                        upstream_token: claim.upstream_token.clone(),
                    },
                },
            )
            .await;
        let now = (self.clock)();
        let Some(ttl) = ttl_until(claim.family_expires_ms, now) else {
            return;
        };
        let result = match released {
            Ok(bytes) => self
                .store
                .compare_and_swap(handle_key, &claim.bytes, &bytes, ttl)
                .await
                .map(|_| ())
                .map_err(Fault::from),
            Err(fault) => Err(fault),
        };
        if let Err(fault) = result {
            tracing::warn!(
                target: "oauthrelay::refresh",
                relay = %self.relay,
                family = %self.family_label(&claim.family_id),
                error = %fault,
                "refresh claim could not be released; it expires with its lease"
            );
        }
    }

    async fn discard(&self, keys: &[&str]) {
        for key in keys {
            if let Err(error) = self.store.delete(key).await {
                tracing::warn!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    ?error,
                    "leftover refresh record could not be removed; it expires on its own"
                );
            }
        }
    }

    async fn reuse_detected(&self, handle_key: &str, record: &Record) -> Result<RefreshOutcome> {
        self.revoke(&record.family_id, record.family_expires_ms, handle_key)
            .await?;
        tracing::warn!(
            target: "oauthrelay::security",
            event = "refresh_token_reuse",
            relay = %self.relay,
            family = %self.family_label(&record.family_id),
            "a rotated refresh token was presented after its grace period; family revoked"
        );
        Ok(RefreshOutcome::InvalidGrant)
    }

    async fn ask_upstream(
        &self,
        upstream: &dyn UpstreamRefresher,
        upstream_token: &str,
    ) -> Result<StoredResponse, UpstreamFailure> {
        match tokio::time::timeout(
            self.timing.upstream_timeout,
            upstream.refresh(upstream_token),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(UpstreamFailure::Request),
        }
    }

    async fn create_family(&self, handle: &str, upstream_token: &str) -> Result<()> {
        let now = (self.clock)();
        let family_expires_ms = now.saturating_add(self.max_lifetime.as_millis() as u64);
        let ttl = ttl_until(family_expires_ms, now).ok_or(Fault::Conflict)?;
        let key = self.handle_key(handle);
        let family_id = random_array::<16>();
        let bytes = self
            .seal(
                RECORD_PURPOSE,
                &key,
                &Record {
                    family_id,
                    family_expires_ms,
                    state: State::Active {
                        upstream_token: upstream_token.to_owned(),
                    },
                },
            )
            .await?;
        if !self.store.put_if_absent(&key, &bytes, ttl).await? {
            return Err(Fault::Conflict);
        }
        if !self
            .store
            .put_if_absent(&self.head_key(&family_id), key.as_bytes(), ttl)
            .await?
        {
            return Err(Fault::Conflict);
        }
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<Loaded>> {
        let Some(entry) = self.store.get(key).await? else {
            return Ok(None);
        };
        let record = self.open(RECORD_PURPOSE, key, &entry.value).await?;
        Ok(Some(Loaded {
            bytes: entry.value,
            record,
        }))
    }

    async fn load_grace_response(&self, key: &str) -> Result<Option<StoredResponse>> {
        let Some(entry) = self.store.get(key).await? else {
            return Ok(None);
        };
        Ok(Some(self.open(GRACE_PURPOSE, key, &entry.value).await?))
    }

    async fn is_revoked(&self, family_id: &[u8; 16]) -> Result<bool> {
        Ok(self.store.get(&self.family_key(family_id)).await?.is_some())
    }

    /// Revokes the family and erases the upstream token it still stores.
    ///
    /// The marker is written first, so a refresh that is in flight sees the revocation when it
    /// finishes. The erase then deletes the family's one token-bearing record, found through the
    /// head pointer and through `known_key` (a record of the family the caller holds); records
    /// that already hold no token stay as tombstones. The erase runs even when the marker already
    /// exists, so a revocation that was interrupted is completed by the next one.
    async fn revoke(
        &self,
        family_id: &[u8; 16],
        family_expires_ms: u64,
        known_key: &str,
    ) -> Result<()> {
        let Some(ttl) = ttl_until(family_expires_ms, (self.clock)()) else {
            return Ok(());
        };
        // Only the marker's presence is read; the random value keeps it unique to this writer, as
        // the store contract requires.
        self.store
            .put_if_absent(&self.family_key(family_id), &random_array::<16>(), ttl)
            .await?;
        let head_key = self.head_key(family_id);
        let head = self
            .store
            .get(&head_key)
            .await?
            .and_then(|entry| String::from_utf8(entry.value).ok());
        if let Some(head) = head.as_deref() {
            self.erase_tokens_if_sealer_available(head).await?;
        }
        if head.as_deref() != Some(known_key) {
            self.erase_tokens_if_sealer_available(known_key).await?;
        }
        Ok(())
    }

    /// `erase_tokens`, except that an unavailable sealer is logged and tolerated. The revocation
    /// marker is already written and every refresh checks it, so the family is dead either way;
    /// the record that was not erased keeps its token only until the family's lifetime ends. The
    /// caller still answers with `invalid_grant` or the provider's error.
    async fn erase_tokens_if_sealer_available(&self, start: &str) -> Result<()> {
        match self.erase_tokens(start).await {
            Err(Fault::SealerUnavailable) => {
                tracing::warn!(
                    target: "oauthrelay::refresh",
                    relay = %self.relay,
                    "revoked family's stored token could not be erased because the sealer is unavailable; the revocation marker still blocks it"
                );
                Ok(())
            }
            other => other,
        }
    }

    /// Follows the chain of rotated records from `start` and deletes the first record that holds
    /// an upstream token.
    async fn erase_tokens(&self, start: &str) -> Result<()> {
        let mut key = start.to_owned();
        for _ in 0..MAX_ERASE_HOPS {
            let loaded = match self.load(&key).await {
                Ok(Some(loaded)) => loaded,
                Ok(None) => return Ok(()),
                // A record this relay cannot open is not worth keeping around.
                Err(Fault::Sealing) => {
                    self.store.delete(&key).await?;
                    return Ok(());
                }
                Err(fault) => return Err(fault),
            };
            match loaded.record.state {
                State::Active { .. } | State::Claimed { .. } => {
                    self.store.delete(&key).await?;
                    return Ok(());
                }
                State::Rotated { successor_key, .. } => key = successor_key,
            }
        }
        tracing::error!(
            target: "oauthrelay::refresh",
            relay = %self.relay,
            "revoked family still has a token-bearing record beyond the erase hop limit"
        );
        Ok(())
    }

    fn handle_key(&self, handle: &str) -> String {
        self.digest_key(HANDLE_KEY_PREFIX, &[handle.as_bytes()])
    }

    /// Where the response of one rotation of the handle stored at `handle_key` is kept. The
    /// claim id keeps two claimants of the same handle from sharing a record.
    fn grace_key(&self, handle_key: &str, claim_id: &[u8; 16]) -> String {
        self.digest_key(GRACE_KEY_PREFIX, &[handle_key.as_bytes(), claim_id])
    }

    fn head_key(&self, family_id: &[u8; 16]) -> String {
        self.digest_key(HEAD_KEY_PREFIX, &[family_id])
    }

    fn family_key(&self, family_id: &[u8; 16]) -> String {
        self.digest_key(REVOKED_KEY_PREFIX, &[family_id])
    }

    fn digest_key(&self, prefix: &str, material: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.relay.as_str().as_bytes());
        hasher.update([0]);
        for part in material {
            hasher.update(part);
            hasher.update([0]);
        }
        format!("{prefix}{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
    }

    fn family_label(&self, family_id: &[u8; 16]) -> String {
        self.family_key(family_id)[REVOKED_KEY_PREFIX.len()..][..12].to_owned()
    }

    fn associated_data(&self, purpose: &str, key: &str) -> Vec<u8> {
        format!("{purpose}\0{}\0{key}", self.relay).into_bytes()
    }

    async fn seal<T: Serialize>(&self, purpose: &str, key: &str, value: &T) -> Result<Vec<u8>> {
        let plaintext = postcard::to_stdvec(value).map_err(|_| Fault::Sealing)?;
        tokio::time::timeout(
            self.timing.sealer_timeout,
            self.sealer
                .seal(&plaintext, &self.associated_data(purpose, key)),
        )
        .await
        .map_err(|_| Fault::SealerUnavailable)?
        .map(String::into_bytes)
        .map_err(Fault::from_seal_error)
    }

    async fn open<T: for<'de> Deserialize<'de>>(
        &self,
        purpose: &str,
        key: &str,
        bytes: &[u8],
    ) -> Result<T> {
        let envelope = std::str::from_utf8(bytes).map_err(|_| Fault::Sealing)?;
        let plaintext = tokio::time::timeout(
            self.timing.sealer_timeout,
            self.sealer
                .unseal(envelope, &self.associated_data(purpose, key)),
        )
        .await
        .map_err(|_| Fault::SealerUnavailable)?
        .map_err(Fault::from_seal_error)?;
        postcard::from_bytes(&plaintext).map_err(|_| Fault::Sealing)
    }

    fn log_fault(&self, fault: &Fault) {
        tracing::error!(
            target: "oauthrelay::refresh",
            relay = %self.relay,
            error = %fault,
            "refresh-token state operation failed"
        );
    }
}

enum Commit {
    Rotated,
    /// Another caller took over the claim, or the family expired meanwhile.
    Lost,
}

fn new_handle() -> String {
    let mut bytes = [0_u8; HANDLE_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    format!("{ROTATING_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_handle_shape(handle: &str) -> bool {
    handle.strip_prefix(ROTATING_PREFIX).is_some_and(|encoded| {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .is_ok_and(|bytes| bytes.len() == HANDLE_BYTES)
    })
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut value = [0_u8; N];
    rand::rng().fill_bytes(&mut value);
    value
}

fn ttl_until(expires_ms: u64, now_ms: u64) -> Option<Duration> {
    (expires_ms > now_ms).then(|| Duration::from_millis(expires_ms - now_ms))
}

fn is_success(response: &StoredResponse) -> bool {
    (200..300).contains(&response.status)
}

/// An OAuth `invalid_grant` error: the upstream has rejected the refresh token itself.
fn is_invalid_grant(response: &StoredResponse) -> bool {
    (400..500).contains(&response.status)
        && serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .is_some_and(|value| {
                value.get("error").and_then(|error| error.as_str()) == Some("invalid_grant")
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        refresh_handle::seal_handle, seal::FlakySealer, Entry, MemoryStore, XChaChaSealer,
    };
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
    };

    const START_MS: u64 = 1_800_000_000_000;
    const GRACE_SECONDS: u64 = 30;
    const LIFETIME_SECONDS: u64 = 1_000;

    /// Wraps a [`MemoryStore`], remembers everything written to it, and can be made to fail.
    struct SpyStore {
        inner: MemoryStore,
        writes: Mutex<Vec<(String, Vec<u8>)>>,
        failing: std::sync::atomic::AtomicBool,
    }

    impl SpyStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: MemoryStore::default(),
                writes: Mutex::new(Vec::new()),
                failing: Default::default(),
            })
        }

        fn fail(&self) -> Result<(), StoreError> {
            if self.failing.load(Ordering::SeqCst) {
                Err(StoreError::Backend(anyhow::anyhow!("store is down")))
            } else {
                Ok(())
            }
        }

        fn record(&self, key: &str, value: &[u8]) {
            self.writes
                .lock()
                .unwrap()
                .push((key.to_owned(), value.to_vec()));
        }
    }

    #[async_trait]
    impl TransientStore for SpyStore {
        async fn put_if_absent(
            &self,
            key: &str,
            value: &[u8],
            ttl: Duration,
        ) -> Result<bool, StoreError> {
            self.fail()?;
            self.record(key, value);
            self.inner.put_if_absent(key, value, ttl).await
        }

        async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
            self.fail()?;
            self.inner.get(key).await
        }

        async fn compare_and_swap(
            &self,
            key: &str,
            expected: &[u8],
            new: &[u8],
            ttl: Duration,
        ) -> Result<bool, StoreError> {
            self.fail()?;
            self.record(key, new);
            self.inner.compare_and_swap(key, expected, new, ttl).await
        }

        async fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.fail()?;
            self.inner.delete(key).await
        }
    }

    /// Answers upstream refreshes from a script, then with a default rotating response.
    #[derive(Default)]
    struct FakeUpstream {
        calls: Mutex<Vec<String>>,
        script: Mutex<VecDeque<Result<StoredResponse, UpstreamFailure>>>,
        delay: Duration,
    }

    impl FakeUpstream {
        fn scripted(script: Vec<Result<StoredResponse, UpstreamFailure>>) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(script.into()),
                ..Default::default()
            })
        }

        fn slow(delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                delay,
                ..Default::default()
            })
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UpstreamRefresher for FakeUpstream {
        async fn refresh(&self, upstream_token: &str) -> Result<StoredResponse, UpstreamFailure> {
            let call = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(upstream_token.to_owned());
                calls.len()
            };
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if let Some(next) = self.script.lock().unwrap().pop_front() {
                return next;
            }
            Ok(json_response(
                200,
                &format!(r#"{{"access_token":"access-{call}","refresh_token":"up-{call}"}}"#),
            ))
        }
    }

    fn json_response(status: u16, body: &str) -> StoredResponse {
        StoredResponse {
            status,
            content_type: Some("application/json".into()),
            body: body.as_bytes().to_vec(),
        }
    }

    fn no_rotation(access: &str) -> Result<StoredResponse, UpstreamFailure> {
        Ok(json_response(
            200,
            &format!(r#"{{"access_token":"{access}","token_type":"Bearer"}}"#),
        ))
    }

    struct Harness {
        store: Arc<SpyStore>,
        sealer: Arc<FlakySealer>,
        now: Arc<AtomicU64>,
        rotator: Arc<Rotator>,
    }

    fn key(name: &str) -> ResourceKey {
        ResourceKey::new(name).unwrap()
    }

    fn fast_timing() -> Timing {
        Timing {
            poll_interval: Duration::from_millis(5),
            resolve_wait: Duration::from_secs(2),
            upstream_timeout: Duration::from_secs(30),
            claim_lease: Duration::from_secs(60),
            sealer_timeout: Duration::from_secs(2),
        }
    }

    impl Harness {
        fn new() -> Self {
            Self::with(SpyStore::new(), "app", fast_timing())
        }

        fn with(store: Arc<SpyStore>, relay: &str, timing: Timing) -> Self {
            let sealer = Arc::new(FlakySealer::new(&[7; 32]));
            let now = Arc::new(AtomicU64::new(START_MS));
            let rotator = Arc::new(Self::rotator(&store, &sealer, &now, relay, timing));
            Self {
                store,
                sealer,
                now,
                rotator,
            }
        }

        fn rotator(
            store: &Arc<SpyStore>,
            sealer: &Arc<FlakySealer>,
            now: &Arc<AtomicU64>,
            relay: &str,
            timing: Timing,
        ) -> Rotator {
            let clock = now.clone();
            Rotator::new(
                store.clone(),
                sealer.clone(),
                key(relay),
                &RefreshTokens {
                    mode: crate::RefreshTokenMode::Rotating,
                    grace_period_seconds: GRACE_SECONDS,
                    max_lifetime_seconds: LIFETIME_SECONDS,
                },
            )
            .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)))
            .with_timing(timing)
        }

        /// Another relay sharing this harness's store, sealer, and clock.
        fn other_relay(&self, relay: &str) -> Rotator {
            Self::rotator(&self.store, &self.sealer, &self.now, relay, fast_timing())
        }

        fn advance(&self, by: Duration) {
            self.now.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
        }

        async fn issue(&self, upstream_token: &str) -> String {
            self.rotator.issue(upstream_token).await.unwrap()
        }

        async fn refresh(&self, handle: &str, upstream: &FakeUpstream) -> RefreshOutcome {
            self.rotator.refresh(handle, upstream).await
        }

        async fn revoked(&self, family: &Loaded) -> bool {
            self.rotator
                .is_revoked(&family.record.family_id)
                .await
                .unwrap()
        }

        async fn load(&self, handle: &str) -> Option<Loaded> {
            self.rotator
                .load(&self.rotator.handle_key(handle))
                .await
                .unwrap()
        }
    }

    fn body(outcome: RefreshOutcome) -> serde_json::Value {
        match outcome {
            RefreshOutcome::Response(response) => {
                assert!((200..300).contains(&response.status), "{response:?}");
                serde_json::from_slice(&response.body).unwrap()
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    fn successor(outcome: RefreshOutcome) -> String {
        body(outcome)["refresh_token"].as_str().unwrap().to_owned()
    }

    fn assert_invalid_grant(outcome: RefreshOutcome) {
        assert!(
            matches!(outcome, RefreshOutcome::InvalidGrant),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn rotates_and_follows_an_upstream_that_rotates() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        assert!(first.starts_with("rrt2."));

        let second = body(harness.refresh(&first, &upstream).await);
        let second_handle = second["refresh_token"].as_str().unwrap();
        assert!(second_handle.starts_with("rrt2."));
        assert_ne!(second_handle, first);
        assert_eq!(second["access_token"], "access-1");
        // The upstream's rotated token is wrapped, never returned.
        assert!(!second.to_string().contains("up-1"));

        let third = body(harness.refresh(second_handle, &upstream).await);
        assert_ne!(third["refresh_token"], second["refresh_token"]);
        assert_eq!(upstream.calls(), ["up-0", "up-1"]);
    }

    #[tokio::test]
    async fn keeps_the_upstream_token_when_the_upstream_does_not_rotate() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![no_rotation("a1"), no_rotation("a2")]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        assert!(second.starts_with("rrt2.") && second != first);
        let reply = body(harness.refresh(&second, &upstream).await);
        // A refresh_token member is added even though the upstream sent none.
        assert!(reply["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("rrt2."));
        assert_eq!(reply["access_token"], "a2");
        assert_eq!(reply["token_type"], "Bearer");
        assert_eq!(upstream.calls(), ["up-0", "up-0"]);
    }

    #[tokio::test]
    async fn the_store_never_holds_a_plaintext_token_or_handle() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-secret-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let _ = harness.refresh(&first, &upstream).await;
        let writes = harness.store.writes.lock().unwrap();
        assert!(writes.len() >= 4);
        for (store_key, value) in writes.iter() {
            assert!(store_key.starts_with("refresh:"), "{store_key}");
            let value = String::from_utf8_lossy(value);
            if store_key.starts_with("refresh:head:") {
                // The head pointer names another store key, which is a hash.
                assert!(value.starts_with("refresh:handle:"));
            } else if store_key.starts_with("refresh:revoked:") {
                assert_eq!(value, "1");
            } else {
                assert!(value.starts_with("v1."), "values are sealed envelopes");
            }
            for secret in ["up-secret-0", "up-1", "access-1", &first, &second] {
                assert!(!store_key.contains(secret) && !value.contains(secret));
            }
        }
        // Handles are not recoverable from keys either.
        let first_key = harness.rotator.handle_key(&first);
        assert!(first_key.starts_with("refresh:handle:"));
        assert!(!first_key.contains(first.trim_start_matches("rrt2.")));
    }

    #[tokio::test]
    async fn a_duplicate_within_the_grace_period_gets_the_same_successor() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let original = body(harness.refresh(&first, &upstream).await);

        harness.advance(Duration::from_secs(GRACE_SECONDS - 1));
        let duplicate = body(harness.refresh(&first, &upstream).await);
        assert_eq!(duplicate, original);
        assert_eq!(
            upstream.calls().len(),
            1,
            "the duplicate must not reach the upstream"
        );
        // Replays do not consume anything: the grace window is measured from the rotation.
        let again = body(harness.refresh(&first, &upstream).await);
        assert_eq!(again, original);

        // The successor works normally.
        let handle = original["refresh_token"].as_str().unwrap();
        assert!(matches!(
            harness.refresh(handle, &upstream).await,
            RefreshOutcome::Response(_)
        ));
    }

    #[tokio::test]
    async fn reuse_after_the_grace_period_revokes_the_family() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let family = harness.load(&first).await.unwrap();
        assert!(!harness.revoked(&family).await);

        harness.advance(Duration::from_secs(GRACE_SECONDS + 1));
        assert_invalid_grant(harness.refresh(&first, &upstream).await);
        assert!(harness.revoked(&family).await);
        // The successor belongs to the same family and no longer works either.
        assert_invalid_grant(harness.refresh(&second, &upstream).await);
        assert_eq!(upstream.calls().len(), 1);
        // The recorded response is gone with the grace window; only tombstones remain.
        let tombstone = harness
            .store
            .get(&harness.rotator.handle_key(&first))
            .await
            .unwrap();
        assert!(tombstone.is_some());
    }

    #[tokio::test]
    async fn revoked_families_reject_handles_even_within_the_grace_period() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let family = harness.load(&first).await.unwrap();
        harness
            .rotator
            .revoke(
                &family.record.family_id,
                family.record.family_expires_ms,
                &harness.rotator.handle_key(&first),
            )
            .await
            .unwrap();
        assert_invalid_grant(harness.refresh(&first, &upstream).await);
        assert_invalid_grant(harness.refresh(&second, &upstream).await);
    }

    #[tokio::test]
    async fn a_family_ends_at_its_maximum_lifetime() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;

        harness.advance(Duration::from_secs(LIFETIME_SECONDS - 100));
        let second = successor(harness.refresh(&first, &upstream).await);
        // The successor inherits the family's end, not a fresh lifetime.
        let stored = harness
            .store
            .get(&harness.rotator.handle_key(&second))
            .await
            .unwrap()
            .unwrap();
        assert!(stored.expires_in <= Duration::from_secs(100));
        let record = harness.load(&second).await.unwrap().record;
        assert_eq!(record.family_expires_ms, START_MS + LIFETIME_SECONDS * 1000);

        harness.advance(Duration::from_secs(101));
        assert_invalid_grant(harness.refresh(&second, &upstream).await);
        assert_eq!(upstream.calls().len(), 1);
    }

    #[tokio::test]
    async fn record_ttls_end_with_the_family() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let ttl = |entry: Option<Entry>| entry.unwrap().expires_in;
        let limit = Duration::from_secs(LIFETIME_SECONDS);
        assert!(
            ttl(harness
                .store
                .get(&harness.rotator.handle_key(&first))
                .await
                .unwrap())
                <= limit
        );

        let second = successor(harness.refresh(&first, &upstream).await);
        let tombstone = ttl(harness
            .store
            .get(&harness.rotator.handle_key(&first))
            .await
            .unwrap());
        assert!(tombstone > Duration::from_secs(LIFETIME_SECONDS - 5) && tombstone <= limit);
        assert!(
            ttl(harness
                .store
                .get(&harness.rotator.handle_key(&second))
                .await
                .unwrap())
                <= limit
        );
        // Response records live for the grace period plus a margin, not the family lifetime.
        let loaded = harness.load(&first).await.unwrap();
        let State::Rotated { claim_id, .. } = loaded.record.state else {
            panic!("expected a rotated record");
        };
        let grace = harness
            .store
            .get(
                &harness
                    .rotator
                    .grace_key(&harness.rotator.handle_key(&first), &claim_id),
            )
            .await
            .unwrap();
        assert!(ttl(grace) <= Duration::from_secs(GRACE_SECONDS) + GRACE_RESPONSE_MARGIN);
    }

    #[tokio::test]
    async fn a_failed_upstream_refresh_releases_the_claim() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![
            Err(UpstreamFailure::Request),
            Ok(json_response(500, r#"{"error":"server_error"}"#)),
            Err(UpstreamFailure::Status(503)),
        ]);
        let first = harness.issue("up-0").await;
        assert!(matches!(
            harness.refresh(&first, &upstream).await,
            RefreshOutcome::UpstreamFailed(UpstreamFailure::Request)
        ));
        // The upstream's own error is passed through, and the handle stays usable.
        match harness.refresh(&first, &upstream).await {
            RefreshOutcome::Response(response) => assert_eq!(response.status, 500),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            harness.refresh(&first, &upstream).await,
            RefreshOutcome::UpstreamFailed(UpstreamFailure::Status(503))
        ));
        let rotated = harness.refresh(&first, &upstream).await;
        assert!(successor(rotated).starts_with("rrt2."));
        assert_eq!(upstream.calls(), ["up-0"; 4]);
        let family = harness.load(&first).await.unwrap();
        assert!(!harness.revoked(&family).await);
    }

    #[tokio::test]
    async fn an_unusable_success_response_releases_the_claim() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![Ok(StoredResponse {
            status: 200,
            content_type: Some("text/plain".into()),
            body: b"access_token=a&refresh_token=b".to_vec(),
        })]);
        let first = harness.issue("up-0").await;
        assert!(matches!(
            harness.refresh(&first, &upstream).await,
            RefreshOutcome::UpstreamUnusable
        ));
        assert!(matches!(
            harness.refresh(&first, &upstream).await,
            RefreshOutcome::Response(_)
        ));
    }

    #[tokio::test]
    async fn an_upstream_invalid_grant_revokes_the_family() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let upstream = FakeUpstream::scripted(vec![Ok(json_response(
            400,
            r#"{"error":"invalid_grant","error_description":"revoked"}"#,
        ))]);
        match harness.refresh(&second, &upstream).await {
            RefreshOutcome::Response(response) => {
                assert_eq!(response.status, 400);
                assert!(String::from_utf8(response.body)
                    .unwrap()
                    .contains("invalid_grant"));
            }
            other => panic!("{other:?}"),
        }
        // Nothing in the family works any more, and the upstream is not asked again.
        assert_invalid_grant(harness.refresh(&second, &upstream).await);
        assert_invalid_grant(harness.refresh(&first, &upstream).await);
        assert_eq!(upstream.calls().len(), 1);
    }

    #[tokio::test]
    async fn a_concurrent_loser_waits_and_gets_the_same_successor() {
        let harness = Harness::new();
        let upstream = FakeUpstream::slow(Duration::from_millis(150));
        let first = harness.issue("up-0").await;
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let rotator = harness.rotator.clone();
                let upstream = upstream.clone();
                let first = first.clone();
                tokio::spawn(async move { rotator.refresh(&first, upstream.as_ref()).await })
            })
            .collect();
        let mut bodies = Vec::new();
        for task in tasks {
            bodies.push(body(task.await.unwrap()));
        }
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "{bodies:?}"
        );
        assert_eq!(upstream.calls().len(), 1, "only the claim winner refreshes");
    }

    #[tokio::test]
    async fn a_loser_gives_up_with_a_retryable_error_when_the_winner_is_slow() {
        let timing = Timing {
            resolve_wait: Duration::from_millis(50),
            ..fast_timing()
        };
        let harness = Harness::with(SpyStore::new(), "app", timing);
        let slow = FakeUpstream::slow(Duration::from_millis(400));
        let first = harness.issue("up-0").await;
        let winner = {
            let rotator = harness.rotator.clone();
            let slow = slow.clone();
            let first = first.clone();
            tokio::spawn(async move { rotator.refresh(&first, slow.as_ref()).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let quick = FakeUpstream::scripted(vec![]);
        assert!(matches!(
            harness.refresh(&first, &quick).await,
            RefreshOutcome::Unavailable
        ));
        assert!(quick.calls().is_empty());
        assert!(matches!(winner.await.unwrap(), RefreshOutcome::Response(_)));
        // Once the winner has recorded the successor the retry is answered from the grace record.
        assert!(matches!(
            harness.refresh(&first, &quick).await,
            RefreshOutcome::Response(_)
        ));
        assert!(quick.calls().is_empty());
    }

    #[tokio::test]
    async fn an_abandoned_claim_can_be_taken_over_after_its_lease() {
        let harness = Harness::new();
        let first = harness.issue("up-0").await;
        // A winner that never finishes, as if its process had been suspended or killed.
        let stuck = FakeUpstream::slow(Duration::from_secs(3600));
        let winner = {
            let rotator = harness.rotator.clone();
            let first = first.clone();
            tokio::spawn(async move { rotator.refresh(&first, stuck.as_ref()).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        let upstream = FakeUpstream::scripted(vec![]);
        harness.advance(Duration::from_secs(61));
        let reply = body(harness.refresh(&first, &upstream).await);
        assert!(reply["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("rrt2."));
        assert_eq!(upstream.calls(), ["up-0"]);
        winner.abort();
    }

    #[tokio::test]
    async fn a_claimant_that_lost_its_claim_leaves_the_winner_intact() {
        let harness = Harness::new();
        let first = harness.issue("up-0").await;
        let slow = FakeUpstream::slow(Duration::from_millis(300));
        let late = {
            let rotator = harness.rotator.clone();
            let first = first.clone();
            let slow = slow.clone();
            tokio::spawn(async move { rotator.refresh(&first, slow.as_ref()).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        harness.advance(Duration::from_secs(61));
        let upstream = FakeUpstream::scripted(vec![]);
        let reply = body(harness.refresh(&first, &upstream).await);
        // The first claimant finishes after its claim was taken over; it must not answer or
        // disturb the successor the new claim holder recorded.
        assert!(matches!(late.await.unwrap(), RefreshOutcome::Unavailable));
        assert_eq!(body(harness.refresh(&first, &upstream).await), reply);
        let handle = reply["refresh_token"].as_str().unwrap();
        assert!(matches!(
            harness.refresh(handle, &upstream).await,
            RefreshOutcome::Response(_)
        ));
        assert_eq!(upstream.calls().len(), 2);
    }

    #[tokio::test]
    async fn sealed_handles_migrate_into_a_rotating_family() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![no_rotation("a1")]);
        let legacy = seal_handle(
            harness.sealer.as_ref(),
            &key("app"),
            "up-legacy",
            START_MS / 1000,
        )
        .await
        .unwrap();
        assert!(legacy.starts_with("rrt1."));
        let handle = successor(harness.refresh(&legacy, &upstream).await);
        assert!(handle.starts_with("rrt2."));
        assert_eq!(upstream.calls(), ["up-legacy"]);
        // The new family wraps the upstream token the sealed handle held.
        let next = FakeUpstream::scripted(vec![]);
        assert!(matches!(
            harness.refresh(&handle, &next).await,
            RefreshOutcome::Response(_)
        ));
        assert_eq!(next.calls(), ["up-legacy"]);

        // Another relay's sealed handle, and a failed upstream, do not migrate.
        let foreign = seal_handle(
            harness.sealer.as_ref(),
            &key("other"),
            "up-x",
            START_MS / 1000,
        )
        .await
        .unwrap();
        assert_invalid_grant(harness.refresh(&foreign, &upstream).await);
        let failing =
            FakeUpstream::scripted(vec![Ok(json_response(400, r#"{"error":"invalid_grant"}"#))]);
        assert!(matches!(
            harness.refresh(&legacy, &failing).await,
            RefreshOutcome::Response(response) if response.status == 400
        ));
    }

    #[tokio::test]
    async fn unknown_foreign_and_malformed_handles_are_invalid_grants() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let handle = harness.issue("up-0").await;
        let other = harness.other_relay("other");
        let unknown = format!("rrt2.{}", URL_SAFE_NO_PAD.encode([9_u8; 32]));
        assert_invalid_grant(harness.refresh(&unknown, &upstream).await);
        // Another relay sharing the store cannot use this relay's handle.
        assert_invalid_grant(other.refresh(&handle, upstream.as_ref()).await);
        for presented in [
            "up-0",
            "",
            "rrt2.",
            "rrt2.short",
            "rrt3.AAAA",
            &handle[..handle.len() - 1],
            &format!("{handle}A"),
        ] {
            assert_invalid_grant(harness.refresh(presented, &upstream).await);
        }
        assert!(upstream.calls().is_empty());
        assert!(matches!(
            harness.refresh(&handle, &upstream).await,
            RefreshOutcome::Response(_)
        ));
    }

    #[tokio::test]
    async fn records_are_bound_to_their_store_key() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = harness.issue("up-1").await;
        // Someone with write access to the store copies one record over another.
        let source = harness
            .store
            .get(&harness.rotator.handle_key(&first))
            .await
            .unwrap()
            .unwrap();
        let target = harness.rotator.handle_key(&second);
        let current = harness.store.get(&target).await.unwrap().unwrap();
        assert!(harness
            .store
            .compare_and_swap(
                &target,
                &current.value,
                &source.value,
                Duration::from_secs(60)
            )
            .await
            .unwrap());
        // An unreadable record is an invalid grant, not a retryable failure, and never reaches
        // the upstream.
        assert_invalid_grant(harness.refresh(&second, &upstream).await);
        assert!(upstream.calls().is_empty());
    }

    #[tokio::test]
    async fn store_failures_fail_closed() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let handle = harness.issue("up-0").await;
        harness.store.failing.store(true, Ordering::SeqCst);
        assert!(matches!(
            harness.refresh(&handle, &upstream).await,
            RefreshOutcome::StoreFailed
        ));
        assert!(harness.rotator.issue("up-1").await.is_err());
        let response = json_response(200, r#"{"refresh_token":"up-secret"}"#);
        assert!(harness.rotator.issue_in_response(&response).await.is_err());
        assert!(upstream.calls().is_empty());
        harness.store.failing.store(false, Ordering::SeqCst);
        assert!(matches!(
            harness.refresh(&handle, &upstream).await,
            RefreshOutcome::Response(_)
        ));
    }

    #[tokio::test]
    async fn issuing_follows_the_same_content_and_fail_closed_rules_as_sealed_mode() {
        let harness = Harness::new();
        // JSON is recognised whatever the content type says.
        let plain = StoredResponse {
            status: 200,
            content_type: Some("text/plain".into()),
            body: br#"{"refresh_token":"up-0","a":1}"#.to_vec(),
        };
        let body = harness
            .rotator
            .issue_in_response(&plain)
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8(body).unwrap().contains("rrt2."));
        // A body that is not a JSON object but carries a refresh token is never returned.
        for body in [
            "access_token=a&refresh_token=up-secret",
            r#"[{"refresh_token":"up-secret"}]"#,
        ] {
            let response = StoredResponse {
                status: 200,
                content_type: Some("application/x-www-form-urlencoded".into()),
                body: body.as_bytes().to_vec(),
            };
            assert_eq!(
                harness
                    .rotator
                    .issue_in_response(&response)
                    .await
                    .unwrap_err(),
                IssueError::UnrecognizedBody,
                "{body}"
            );
        }
        // Non-2xx and bodies without a refresh token pass through.
        for response in [
            json_response(400, "refresh_token=x"),
            json_response(200, "access_token=a&token_type=Bearer"),
        ] {
            assert!(harness
                .rotator
                .issue_in_response(&response)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn only_an_invalid_grant_error_revokes_the_family() {
        let harness = Harness::new();
        let first = harness.issue("up-0").await;
        let family = harness.load(&first).await.unwrap();
        let upstream = FakeUpstream::scripted(vec![
            Ok(json_response(401, r#"{"error":"invalid_client"}"#)),
            Ok(json_response(400, r#"{"error":"invalid_request"}"#)),
            Ok(json_response(
                400,
                r#"{"error":"invalid_scope","note":"invalid_grant"}"#,
            )),
            Ok(json_response(403, "invalid_grant")),
            Ok(json_response(429, r#"{"error":"temporarily_unavailable"}"#)),
            Ok(json_response(200, r#"{"error":"invalid_grant"}"#)),
        ]);
        for expected in [401, 400, 400, 403, 429] {
            match harness.refresh(&first, &upstream).await {
                RefreshOutcome::Response(response) => assert_eq!(response.status, expected),
                other => panic!("{other:?}"),
            }
            assert!(!harness.revoked(&family).await, "status {expected}");
        }
        // A 2xx is a success whatever it says; it has no token to wrap, so it is unusable.
        assert!(matches!(
            harness.refresh(&first, &upstream).await,
            RefreshOutcome::Response(_)
        ));
        // The handle was released every time and still works.
        assert_eq!(upstream.calls().len(), 6);
        assert!(!harness.revoked(&family).await);

        // The JSON `invalid_grant` error revokes whatever content type it arrives with.
        let plain = FakeUpstream::scripted(vec![Ok(StoredResponse {
            status: 400,
            content_type: Some("text/plain".into()),
            body: br#"{"error":"invalid_grant"}"#.to_vec(),
        })]);
        let second = harness.issue("up-1").await;
        let second_family = harness.load(&second).await.unwrap();
        assert!(matches!(
            harness.refresh(&second, &plain).await,
            RefreshOutcome::Response(response) if response.status == 400
        ));
        assert!(harness.revoked(&second_family).await);
    }

    #[tokio::test]
    async fn an_unavailable_sealer_is_not_tampering() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let legacy = seal_handle(
            harness.sealer.as_ref(),
            &key("app"),
            "up-legacy",
            START_MS / 1000,
        )
        .await
        .unwrap();

        // Opening is down: the handle is neither rejected nor revoked, and the upstream is not
        // asked.
        harness.sealer.set_unseal_down(true);
        for handle in [&first, &legacy] {
            let outcome = harness.refresh(handle, &upstream).await;
            assert!(
                matches!(outcome, RefreshOutcome::SealerUnavailable),
                "{outcome:?}"
            );
        }
        assert!(upstream.calls().is_empty());
        harness.sealer.set_unseal_down(false);
        let family = harness.load(&first).await.unwrap();
        assert!(!harness.revoked(&family).await);

        // Sealing is down: the claim cannot be written, so the upstream is not asked.
        harness.sealer.set_seal_down(true);
        let outcome = harness.refresh(&first, &upstream).await;
        assert!(
            matches!(outcome, RefreshOutcome::SealerUnavailable),
            "{outcome:?}"
        );
        assert!(upstream.calls().is_empty());
        harness.sealer.set_seal_down(false);

        // Once the sealer is back, the same handle and the legacy handle both still work.
        assert!(successor(harness.refresh(&first, &upstream).await).starts_with("rrt2."));
        assert!(successor(harness.refresh(&legacy, &upstream).await).starts_with("rrt2."));
        assert_eq!(upstream.calls(), ["up-0", "up-legacy"]);
    }

    #[tokio::test]
    async fn issuing_with_an_unavailable_sealer_stores_nothing() {
        let harness = Harness::new();
        harness.sealer.set_seal_down(true);
        assert_eq!(
            harness.rotator.issue("up-0").await,
            Err(IssueError::SealerUnavailable)
        );
        assert!(harness.store.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn erasing_keeps_records_the_sealer_could_not_open() {
        let harness = Harness::new();
        let first = harness.issue("up-0").await;
        let handle_key = harness.rotator.handle_key(&first);

        harness.sealer.set_unseal_down(true);
        assert!(matches!(
            harness.rotator.erase_tokens(&handle_key).await,
            Err(Fault::SealerUnavailable)
        ));
        harness.sealer.set_unseal_down(false);
        assert!(harness.load(&first).await.is_some());

        // A record that really cannot be opened is discarded.
        let other_install = XChaChaSealer::new(&[9; 32], None).unwrap();
        let foreign = other_install
            .seal(b"not a record", b"unrelated")
            .await
            .unwrap();
        harness
            .store
            .inner
            .put_if_absent(
                "refresh:handle:foreign",
                foreign.as_bytes(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        harness
            .rotator
            .erase_tokens("refresh:handle:foreign")
            .await
            .unwrap();
        assert!(harness
            .store
            .inner
            .get("refresh:handle:foreign")
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_claim_holder_finishes_within_the_lease_even_when_every_seal_times_out_late() {
        let timing = Timing::default();
        assert!(
            timing.upstream_timeout + 4 * timing.sealer_timeout < timing.claim_lease,
            "{timing:?}"
        );
    }

    #[tokio::test]
    async fn a_hanging_sealer_is_cut_off_and_reported_unavailable() {
        let timing = Timing {
            sealer_timeout: Duration::from_millis(50),
            ..fast_timing()
        };
        let harness = Harness::with(SpyStore::new(), "app", timing);
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let legacy = seal_handle(
            harness.sealer.as_ref(),
            &key("app"),
            "up-legacy",
            START_MS / 1000,
        )
        .await
        .unwrap();

        harness.sealer.set_hang(true);
        for handle in [&first, &legacy] {
            let outcome =
                tokio::time::timeout(Duration::from_secs(5), harness.refresh(handle, &upstream))
                    .await
                    .expect("the sealer timeout bounds the request");
            assert!(
                matches!(outcome, RefreshOutcome::SealerUnavailable),
                "{outcome:?}"
            );
        }
        assert!(upstream.calls().is_empty());
        let issued = tokio::time::timeout(Duration::from_secs(5), harness.rotator.issue("up-1"))
            .await
            .expect("the sealer timeout bounds issuing");
        assert_eq!(issued, Err(IssueError::SealerUnavailable));
    }

    #[tokio::test]
    async fn a_seal_failure_inside_commit_leaves_the_claim_to_expire_and_returns_no_token() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let handle_key = harness.rotator.handle_key(&first);
        let writes_before = harness.store.writes.lock().unwrap().len();

        // The claim and the grace response seal; the successor record does not.
        harness.sealer.fail_seals_after(2);
        let outcome = harness.refresh(&first, &upstream).await;
        assert!(
            matches!(outcome, RefreshOutcome::SealerUnavailable),
            "{outcome:?}"
        );
        // The upstream was asked, so its token was spent in this attempt.
        assert_eq!(upstream.calls(), ["up-0"]);

        // Nothing but the claim remains: no grace response, no successor.
        let writes = harness.store.writes.lock().unwrap().clone();
        let claim_bytes = writes[writes_before..]
            .iter()
            .find(|(key, _)| *key == handle_key)
            .map(|(_, value)| value.clone())
            .expect("the claim was written");
        for (key, _) in &writes[writes_before..] {
            if *key != handle_key {
                assert!(
                    harness.store.inner.get(key).await.unwrap().is_none(),
                    "{key} should have been removed"
                );
            }
        }
        let stored = harness.store.inner.get(&handle_key).await.unwrap().unwrap();
        assert_eq!(stored.value, claim_bytes, "the claimed record is unchanged");
        harness.sealer.reset_budgets();
        let loaded = harness.load(&first).await.unwrap();
        assert!(matches!(loaded.record.state, State::Claimed { .. }));

        // While the claim is fresh the handle is held; once the lease passes it is taken over.
        harness.advance(Duration::from_secs(61));
        let second = successor(harness.refresh(&first, &upstream).await);
        assert!(second.starts_with("rrt2."));
        assert_eq!(upstream.calls(), ["up-0", "up-0"]);
    }

    #[tokio::test]
    async fn an_unavailable_sealer_does_not_turn_a_revocation_into_an_error() {
        let harness = Harness::new();
        let first = harness.issue("up-0").await;
        let family = harness.load(&first).await.unwrap();
        let handle_key = harness.rotator.handle_key(&first);

        // Upstream invalid_grant: the family is revoked and the provider's error comes back even
        // though the stored token could not be opened to erase it.
        let rejecting = FakeUpstream::scripted(vec![Ok(StoredResponse {
            status: 400,
            content_type: Some("application/json".into()),
            body: br#"{"error":"invalid_grant"}"#.to_vec(),
        })]);
        harness.sealer.fail_unseals_after(1);
        assert!(matches!(
            harness.refresh(&first, &rejecting).await,
            RefreshOutcome::Response(response) if response.status == 400
        ));
        harness.sealer.reset_budgets();
        assert!(harness.revoked(&family).await);
        assert!(harness
            .store
            .inner
            .get(&handle_key)
            .await
            .unwrap()
            .is_some());
        assert_invalid_grant(harness.refresh(&first, &rejecting).await);
    }

    #[tokio::test]
    async fn an_unavailable_sealer_does_not_turn_reuse_detection_into_an_error() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let family = harness.load(&first).await.unwrap();
        harness.advance(Duration::from_secs(GRACE_SECONDS + 1));

        // The record is read once to see that the handle was rotated; the erase that follows
        // cannot open anything.
        harness.sealer.fail_unseals_after(1);
        assert_invalid_grant(harness.refresh(&first, &upstream).await);
        harness.sealer.reset_budgets();
        assert!(harness.revoked(&family).await);
        assert_invalid_grant(harness.refresh(&second, &upstream).await);
    }

    #[tokio::test]
    async fn sealed_handles_past_the_maximum_lifetime_are_rejected() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let issued = START_MS / 1000;
        let handle = async |issued_at: u64| {
            seal_handle(harness.sealer.as_ref(), &key("app"), "up-legacy", issued_at)
                .await
                .unwrap()
        };
        // Just inside the lifetime migrates; at and beyond it does not reach the upstream.
        let recent = handle(issued - LIFETIME_SECONDS + 1).await;
        assert!(matches!(
            harness.refresh(&recent, &upstream).await,
            RefreshOutcome::Response(_)
        ));
        let expired = handle(issued - LIFETIME_SECONDS).await;
        assert_invalid_grant(harness.refresh(&expired, &upstream).await);
        assert_invalid_grant(harness.refresh(&handle(0).await, &upstream).await);
        assert_eq!(upstream.calls().len(), 1);
    }

    #[tokio::test]
    async fn revocation_erases_the_stored_upstream_token() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let third = successor(harness.refresh(&second, &upstream).await);
        let family = harness.load(&first).await.unwrap();
        let head = harness.rotator.handle_key(&third);
        assert!(harness.load(&third).await.is_some());

        // Reuse of the oldest handle erases the newest record, which held the only token.
        harness.advance(Duration::from_secs(GRACE_SECONDS + 1));
        assert_invalid_grant(harness.refresh(&first, &upstream).await);
        assert!(harness.revoked(&family).await);
        assert!(harness.store.get(&head).await.unwrap().is_none());
        // Superseded records stay as token-free tombstones until the family expires.
        for rotated in [&first, &second] {
            assert!(matches!(
                harness.load(rotated).await.unwrap().record.state,
                State::Rotated { .. }
            ));
        }
    }

    #[tokio::test]
    async fn revocation_finds_the_token_when_the_head_pointer_is_missing() {
        let harness = Harness::new();
        let upstream = FakeUpstream::scripted(vec![]);
        let first = harness.issue("up-0").await;
        let second = successor(harness.refresh(&first, &upstream).await);
        let third = successor(harness.refresh(&second, &upstream).await);
        let family = harness.load(&first).await.unwrap();
        harness
            .store
            .delete(&harness.rotator.head_key(&family.record.family_id))
            .await
            .unwrap();
        harness.advance(Duration::from_secs(GRACE_SECONDS + 1));
        // The chain from the presented handle leads to the newest record.
        assert_invalid_grant(harness.refresh(&first, &upstream).await);
        assert!(harness.load(&third).await.is_none());
    }

    #[tokio::test]
    async fn an_upstream_invalid_grant_erases_the_claimed_record() {
        let harness = Harness::new();
        let first = harness.issue("up-0").await;
        let upstream =
            FakeUpstream::scripted(vec![Ok(json_response(400, r#"{"error":"invalid_grant"}"#))]);
        harness.refresh(&first, &upstream).await;
        assert!(harness.load(&first).await.is_none());
    }

    #[tokio::test]
    async fn a_family_revoked_while_a_refresh_is_in_flight_gets_no_tokens() {
        for erase in [false, true] {
            let harness = Harness::new();
            let first = harness.issue("up-0").await;
            let family = harness.load(&first).await.unwrap();
            let slow = FakeUpstream::slow(Duration::from_millis(200));
            let winner = {
                let rotator = harness.rotator.clone();
                let first = first.clone();
                let slow = slow.clone();
                tokio::spawn(async move { rotator.refresh(&first, slow.as_ref()).await })
            };
            tokio::time::sleep(Duration::from_millis(40)).await;
            if erase {
                // A full revocation deletes the claimed record out from under the winner.
                harness
                    .rotator
                    .revoke(
                        &family.record.family_id,
                        family.record.family_expires_ms,
                        &harness.rotator.handle_key(&first),
                    )
                    .await
                    .unwrap();
            } else {
                // Only the marker is in place when the winner commits, so the winner itself must
                // notice and withhold the tokens it was about to return.
                assert!(harness
                    .store
                    .put_if_absent(
                        &harness.rotator.family_key(&family.record.family_id),
                        b"1",
                        Duration::from_secs(60)
                    )
                    .await
                    .unwrap());
            }
            assert!(
                matches!(winner.await.unwrap(), RefreshOutcome::InvalidGrant),
                "erase: {erase}"
            );
            // Nothing the winner wrote survives: the old record is a tombstone or gone, and
            // there is no successor to refresh.
            let after = FakeUpstream::scripted(vec![]);
            assert_invalid_grant(harness.refresh(&first, &after).await);
            assert!(after.calls().is_empty());
            let writes = harness.store.writes.lock().unwrap().clone();
            for (key, _) in writes
                .iter()
                .filter(|(key, _)| key.starts_with("refresh:handle:"))
            {
                if *key == harness.rotator.handle_key(&first) {
                    continue;
                }
                assert!(
                    harness.store.get(key).await.unwrap().is_none(),
                    "successor record must be removed (erase: {erase})"
                );
            }
        }
    }

    #[tokio::test]
    async fn issuing_substitutes_only_responses_that_carry_a_refresh_token() {
        let harness = Harness::new();
        let with = json_response(201, r#"{"access_token":"a","refresh_token":"up-0","x":1}"#);
        let replaced = harness
            .rotator
            .issue_in_response(&with)
            .await
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&replaced).unwrap();
        let handle = value["refresh_token"].as_str().unwrap();
        assert!(handle.starts_with("rrt2."));
        assert!(!String::from_utf8(replaced.clone())
            .unwrap()
            .contains("up-0"));
        assert_eq!(value["x"], 1);
        assert!(harness.load(handle).await.is_some());

        for response in [
            json_response(200, r#"{"access_token":"a"}"#),
            json_response(200, r#"{"refresh_token":""}"#),
            json_response(400, r#"{"refresh_token":"up-0"}"#),
        ] {
            assert!(harness
                .rotator
                .issue_in_response(&response)
                .await
                .unwrap()
                .is_none());
        }
    }
}
