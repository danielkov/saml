//! Anti-replay protection for SAML assertion IDs.
//!
//! Callers MUST dedupe `assertion_id` against a store to prevent
//! attackers replaying a captured assertion within its validity window.
//! This module provides a [`ReplayCache`] trait and an in-memory default.
//!
//! SAML 2.0 Core §2.5.1.5 OneTimeUse: when present, the relying party
//! MUST consume the assertion at most once. We treat replay as forbidden
//! for ALL assertions (not just OneTimeUse-marked ones) — that's the
//! safer default. Callers who want OneTimeUse-only semantics can wrap
//! [`InMemoryReplayCache`] with their own conditional logic.
//!
//! The cache is consulted by
//! [`ServiceProvider::consume_response`](crate::sp::ServiceProvider::consume_response)
//! AFTER signature verification and all other spec checks succeed — we
//! never pollute the cache with assertion IDs from forged or malformed
//! responses. Wire a cache by setting
//! [`ConsumeResponse::replay_cache`](crate::sp::ConsumeResponse::replay_cache)
//! to `Some(&cache)`; passing `None` disables the check.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::error::Error;

/// Caller-implemented anti-replay store, consulted after signature
/// verification by [`ServiceProvider::consume_response`](crate::sp::ServiceProvider::consume_response).
///
/// Implementations MUST be safe to share across threads (`Send + Sync`)
/// — the SP is typically wrapped in an `Arc` shared by every request
/// handler.
///
/// # Contract
///
/// - `check_and_insert(id, expires_at)` returns `Ok(true)` when the entry
///   was newly inserted (i.e. the assertion is fresh).
/// - It returns `Ok(false)` when the same `assertion_id` was previously
///   inserted AND has not yet expired — this is a replay, and the SP will
///   surface it as [`Error::AssertionReplay`].
/// - Backend failures (e.g. a network blip against a Redis-backed store)
///   should be returned as [`Error`] variants — typically
///   [`Error::ReplayCache`] — and the SP will propagate them unchanged.
///
/// The check happens AFTER signature verification so a bad-actor flood
/// of unsigned garbage cannot exhaust the cache.
pub trait ReplayCache: Send + Sync {
    /// Returns `Ok(true)` if `assertion_id` was newly inserted; `Ok(false)`
    /// if it was already present (a replay). Errors propagate as
    /// `Error::ReplayCache` from `consume_response`.
    fn check_and_insert(
        &self,
        assertion_id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, Error>;
}

/// Default in-memory [`ReplayCache`] implementation backed by a
/// `Mutex<HashMap<String, SystemTime>>`.
///
/// Suitable for single-process deployments. Multi-instance deployments
/// SHOULD implement [`ReplayCache`] against a shared store (Redis,
/// memcached, a SQL table with `(id, expires_at)` and a unique
/// constraint) so a replay caught by one process is rejected by every
/// process.
///
/// # Eviction
///
/// Expired entries are evicted lazily on every call to
/// [`check_and_insert`](Self::check_and_insert) — there is no background
/// task. Memory therefore tracks the number of *live* (within-TTL)
/// assertions plus whatever stragglers have not been touched since they
/// expired.
///
/// # Capacity
///
/// `capacity` is a hard upper bound on the number of stored entries.
/// When the cache is full AND the lazy sweep did not free a slot,
/// [`check_and_insert`](Self::check_and_insert) returns
/// [`Error::ReplayCacheFull`] rather than silently evicting an entry.
/// Failing closed is the safer default: under load the SP refuses new
/// logins rather than risk accepting a replay of an entry it forgot.
/// Tune `capacity` to comfortably exceed `peak_logins_per_second *
/// max_assertion_lifetime_seconds`.
#[derive(Debug)]
pub struct InMemoryReplayCache {
    capacity: usize,
    inner: Mutex<HashMap<String, SystemTime>>,
}

impl InMemoryReplayCache {
    /// Default capacity. Roughly one million entries' worth of headroom
    /// at ~10 logins/second sustained with 5-minute assertion lifetimes
    /// — order-of-magnitude headroom on top of that.
    pub const DEFAULT_CAPACITY: usize = 100_000;

    /// Construct an in-memory cache with the given hard capacity.
    ///
    /// `capacity_hint` is treated as both an initial-capacity hint for
    /// the backing `HashMap` and the hard ceiling enforced on every
    /// insert.
    pub fn new(capacity_hint: usize) -> Self {
        Self {
            capacity: capacity_hint,
            inner: Mutex::new(HashMap::with_capacity(capacity_hint)),
        }
    }

    /// How many entries (expired or live) the cache currently holds.
    /// Useful for tests and metrics.
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.len())
    }

    /// `true` when no entries are stored. Strictly a convenience wrapper
    /// around `self.len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(
        &self,
        assertion_id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, Error> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_err| Error::ReplayCache {
                reason: "in-memory replay cache mutex poisoned",
            })?;

        // Lazy sweep: drop any entry whose expires_at is in the past.
        // We compute `now` once and reuse it for both the sweep and the
        // membership check so a single tick of the wall clock can't see
        // an entry as both expired (for sweep) and live (for replay).
        let now = SystemTime::now();
        guard.retain(|_, exp| *exp > now);

        // Treat a *live* (within-TTL) prior entry as a replay. An
        // already-expired entry would have been swept above, so any
        // entry we observe here is either fresh or one we just
        // inserted in a previous call within its TTL.
        if guard.contains_key(assertion_id) {
            return Ok(false);
        }

        // Hard capacity: fail closed rather than silently evict.
        if guard.len() >= self.capacity {
            return Err(Error::ReplayCacheFull);
        }

        guard.insert(assertion_id.to_owned(), expires_at);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Capacity larger than the test workload so the only path that can
    /// fail is the actual logic under test.
    const TEST_CAPACITY: usize = 64;

    fn future_expiry(secs: u64) -> SystemTime {
        SystemTime::now()
            .checked_add(Duration::from_secs(secs))
            .expect("future_expiry: fixed offset fits in SystemTime")
    }

    fn past_expiry(secs: u64) -> SystemTime {
        SystemTime::now()
            .checked_sub(Duration::from_secs(secs))
            .expect("past_expiry: fixed offset fits in SystemTime")
    }

    #[test]
    fn replay_first_time_insert_succeeds() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let inserted = cache
            .check_and_insert("_a1", future_expiry(300))
            .expect("first insert");
        assert!(inserted, "first insert returns true");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_duplicate_within_ttl_rejected() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let first = cache
            .check_and_insert("_a1", future_expiry(300))
            .expect("first insert");
        assert!(first);
        let second = cache
            .check_and_insert("_a1", future_expiry(300))
            .expect("second insert");
        assert!(!second, "duplicate within TTL returns false");
        // Cache still holds exactly one entry — we didn't accidentally
        // double-insert.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_after_expiry_succeeds() {
        // We can't move the wall clock backward, so use a past
        // `expires_at` to simulate an entry that has already aged out.
        // The lazy sweep on the next call should drop it, after which
        // the same id can be inserted again.
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let inserted = cache
            .check_and_insert("_a1", past_expiry(1))
            .expect("insert with past expiry");
        assert!(inserted);
        // First call already inserted the entry. Any subsequent call
        // will sweep it because its `expires_at` is in the past.
        let again = cache
            .check_and_insert("_a1", future_expiry(300))
            .expect("re-insert after expiry");
        assert!(
            again,
            "an entry whose expires_at is in the past must be swept and re-insertable"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_capacity_full_errors() {
        let cache = InMemoryReplayCache::new(2);
        cache
            .check_and_insert("_a", future_expiry(300))
            .expect("first");
        cache
            .check_and_insert("_b", future_expiry(300))
            .expect("second");
        let err = cache
            .check_and_insert("_c", future_expiry(300))
            .expect_err("capacity exhausted");
        assert!(
            matches!(err, Error::ReplayCacheFull),
            "expected Error::ReplayCacheFull, got {err:?}"
        );
    }

    #[test]
    fn default_constructs_with_default_capacity() {
        let cache = InMemoryReplayCache::default();
        assert!(cache.is_empty());
        cache
            .check_and_insert("_a", future_expiry(300))
            .expect("default cache accepts inserts");
        assert_eq!(cache.len(), 1);
    }

    /// The trait must be object-safe; `ConsumeResponse::replay_cache`
    /// stores a `&dyn ReplayCache`, so this is load-bearing.
    #[test]
    fn replay_cache_is_object_safe() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let as_dyn: &dyn ReplayCache = &cache;
        as_dyn
            .check_and_insert("_a", future_expiry(60))
            .expect("dyn dispatch works");
    }
}
