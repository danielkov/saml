//! Anti-replay protection for SAML assertion IDs.
//!
//! Callers MUST dedupe `assertion_id` against a store to prevent
//! attackers replaying a captured assertion within its validity window.
//! This module provides a [`ReplayCache`] trait and an in-memory default.
//!
//! SAML 2.0 Core §2.5.1.5 OneTimeUse: when present, the relying party
//! MUST consume the assertion at most once. By default we treat replay as
//! forbidden for ALL assertions — that's the safer default. Callers who
//! need to accommodate IdPs that legitimately reuse `AssertionID` on
//! retry can downshift to [`ReplayMode::OneTimeUseOnly`] to enforce only
//! the spec-mandated minimum, or to [`ReplayMode::Off`] when replay
//! defense for ordinary assertions lives entirely in caller code.
//! `OneTimeUse` still fails closed unless this library can atomically insert
//! the assertion into a configured cache.
//!
//! The cache is consulted by
//! [`ServiceProvider::consume_response`](crate::sp::ServiceProvider::consume_response)
//! AFTER signature verification and all other spec checks succeed — we
//! never pollute the cache with assertion IDs from forged or malformed
//! responses. Wire a cache by setting
//! [`ConsumeResponse::replay_cache`](crate::sp::ConsumeResponse::replay_cache)
//! to `Some(&cache)`; passing `None` disables the optional check for ordinary
//! assertions but makes a `OneTimeUse` assertion unenforceable and rejected.

use std::collections::{HashMap, HashSet};
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
/// - `check_and_insert(entries, now)` returns `Ok(true)` only when every entry
///   was newly inserted.
/// - It returns `Ok(false)` when any key was previously inserted and has not
///   yet expired. No entry from that call may be inserted in this case.
/// - Each `expires_at` is the last instant the credential can still pass
///   validation — the assertion's `NotOnOrAfter` plus the `clock_skew` the
///   SP validated it under, not the raw `NotOnOrAfter`. Implementations MUST
///   retain the entry until then; dropping it earlier reopens a replay
///   window during which the assertion still validates.
/// - Expiry and lazy eviction MUST use the supplied `now`, which is the same
///   clock value used to validate the credential. Consulting a second wall
///   clock can immediately evict a freshly validated tombstone when clocks
///   differ.
/// - Backend failures (e.g. a network blip against a Redis-backed store)
///   should be returned as [`Error`] variants — typically
///   [`Error::ReplayCache`] — and the SP will propagate them unchanged.
///
/// The check happens AFTER signature verification so a bad-actor flood
/// of unsigned garbage cannot exhaust the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplayNamespace {
    /// A SAML assertion ID.
    Assertion,
    /// A proxy login transaction.
    ProxyTransaction,
    /// An authenticated IdP-side `<samlp:ArtifactResolve>/@ID`.
    ArtifactResolve,
}

/// One namespaced replay tombstone to reserve atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayEntry<'a> {
    pub namespace: ReplayNamespace,
    pub id: &'a str,
    pub expires_at: SystemTime,
}

impl<'a> ReplayEntry<'a> {
    pub fn assertion(id: &'a str, expires_at: SystemTime) -> Self {
        Self {
            namespace: ReplayNamespace::Assertion,
            id,
            expires_at,
        }
    }

    pub fn proxy_transaction(id: &'a str, expires_at: SystemTime) -> Self {
        Self {
            namespace: ReplayNamespace::ProxyTransaction,
            id,
            expires_at,
        }
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub(crate) fn artifact_resolve(id: &'a str, expires_at: SystemTime) -> Self {
        Self {
            namespace: ReplayNamespace::ArtifactResolve,
            id,
            expires_at,
        }
    }
}

pub trait ReplayCache: Send + Sync {
    /// Atomically reserve all `entries` and report whether they were fresh.
    /// Returns `Ok(true)` only if every entry was inserted and `Ok(false)` if
    /// any live prior entry conflicts. Errors propagate from response
    /// consumption without inserting a partial batch.
    ///
    /// # Atomicity
    ///
    /// This MUST be atomic and linearizable: a single indivisible
    /// insert-if-all-absent. Two concurrent calls containing the same key must
    /// not both report "not seen", and a multi-entry call MUST commit all or
    /// none. The proxy uses one namespaced transaction tombstone whose
    /// `InResponseTo` correlation binds it to the validated assertion; other
    /// callers may still need an all-or-nothing batch.
    ///
    /// A check-then-insert built from two operations is a race, and the
    /// window is exactly the one an attacker replays into. This is not a
    /// quality-of-implementation note: `Proxy::consume_upstream_response`
    /// requires a cache precisely so that one upstream authentication yields
    /// one downstream assertion, and a non-atomic implementation silently
    /// removes that guarantee. Back it with `Mutex`/`RwLock`, Redis `SET NX`,
    /// or an `INSERT` on a unique index — not a `get` followed by a `put`.
    fn check_and_insert(&self, entries: &[ReplayEntry<'_>], now: SystemTime)
    -> Result<bool, Error>;
}

/// Default in-memory [`ReplayCache`] implementation backed by a
/// `Mutex<HashMap<(ReplayNamespace, String), SystemTime>>`.
///
/// Suitable for single-process deployments. Multi-instance deployments
/// SHOULD implement [`ReplayCache`] against a shared store (Redis,
/// memcached, or a SQL table whose unique key is `(namespace, id)` and whose
/// separate `expires_at` column controls retention) so a replay caught by one
/// process is rejected by every process. Including `expires_at` in the unique
/// key is unsafe: the same live ID could then be inserted again with a
/// different expiry.
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
/// (max_assertion_lifetime_seconds + clock_skew_seconds)`.
#[derive(Debug)]
pub struct InMemoryReplayCache {
    capacity: usize,
    inner: Mutex<HashMap<(ReplayNamespace, String), SystemTime>>,
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

/// Selects which subset of inbound assertions are submitted to the
/// [`ReplayCache`] from
/// [`ServiceProvider::consume_response`](crate::sp::ServiceProvider::consume_response).
///
/// Per SAML 2.0 Core §2.5.1.5 and §3.4.5 the `<saml:OneTimeUse>` condition
/// MUST be enforced (single-use only); for assertions that do not carry it,
/// replay defense is recommended but not strictly mandatory. Some
/// real-world IdPs reuse `AssertionID` values on retry, which means strict
/// replay defense rejects legitimate retries as replays. `ReplayMode` is
/// the knob to relax that behavior when (and only when) the deployment
/// requires it.
///
/// Defaults to [`ReplayMode::All`] so that existing callers — and callers
/// who don't think about this knob — get the safest behavior.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayMode {
    /// Reject any `AssertionID` previously seen, regardless of whether the
    /// assertion carries `<OneTimeUse/>`. This is the safe, strict default
    /// and matches the crate's pre-`ReplayMode` behavior. Choose this
    /// unless you have a concrete reason not to.
    #[default]
    All,
    /// Only reject `AssertionID`s from assertions whose `<Conditions>`
    /// element carries `<OneTimeUse/>`. Matches the spec-mandated minimum
    /// (Core §2.5.1.5). Use this when the IdP legitimately reuses
    /// `AssertionID` on retry — strict mode would falsely reject the
    /// second delivery as a replay. The trade-off is a wider window for
    /// attacker replay of non-`OneTimeUse` assertions; pair this with
    /// short assertion lifetimes and out-of-band correlation
    /// (`SessionIndex`, `NameID`, etc.) when applicable.
    OneTimeUseOnly,
    /// Disable replay defense entirely — the cache is never consulted from
    /// `consume_response` for ordinary assertions. A literal `<OneTimeUse>`
    /// still fails closed with `Error::OneTimeUseUnenforceable`. Choose this
    /// only when the caller dedupes
    /// `Identity::assertion_id` against its own store, or when the caller
    /// explicitly accepts the residual replay risk. Misusing this knob
    /// re-opens the SAML 2.0 replay attack surface in full.
    Off,
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(
        &self,
        entries: &[ReplayEntry<'_>],
        now: SystemTime,
    ) -> Result<bool, Error> {
        let mut guard = self.inner.lock().map_err(|_err| Error::ReplayCache {
            reason: "in-memory replay cache mutex poisoned",
        })?;

        // Lazy sweep: drop any entry whose expires_at is in the past.
        // We compute `now` once and reuse it for both the sweep and the
        // membership check so a single tick of the wall clock can't see
        // an entry as both expired (for sweep) and live (for replay).
        guard.retain(|_, exp| *exp > now);

        // Check the complete batch before changing the map. Duplicate keys in
        // one batch cannot all be fresh, and a live stored key is a replay.
        let mut pending = HashSet::with_capacity(entries.len());
        for entry in entries {
            let key = (entry.namespace, entry.id);
            if !pending.insert(key)
                || guard
                    .keys()
                    .any(|(namespace, id)| *namespace == entry.namespace && id == entry.id)
            {
                return Ok(false);
            }
        }

        // Hard capacity: fail closed rather than silently evict.
        if guard
            .len()
            .checked_add(entries.len())
            .is_none_or(|required| required > self.capacity)
        {
            return Err(Error::ReplayCacheFull);
        }

        for entry in entries {
            guard.insert((entry.namespace, entry.id.to_owned()), entry.expires_at);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract on `check_and_insert` is that it is atomic, and the whole
    /// proxy one-authentication/one-assertion guarantee rests on it. A
    /// check-then-insert would let two threads both see "not seen" and both
    /// proceed.
    ///
    /// Hammers the same key from many threads at once and requires exactly one
    /// winner. This cannot prove atomicity, but it does fail loudly on the
    /// obvious non-atomic implementation.
    #[test]
    fn check_and_insert_admits_exactly_one_winner_under_contention() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache = Arc::new(InMemoryReplayCache::new(1024));
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_hours(1))
            .expect("representable");
        let now = SystemTime::now();
        let fresh_count = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for _ in 0..32 {
                let cache = Arc::clone(&cache);
                let fresh_count = Arc::clone(&fresh_count);
                scope.spawn(move || {
                    if cache
                        .check_and_insert(
                            &[ReplayEntry::assertion("_contended-assertion", expires_at)],
                            now,
                        )
                        .expect("cache available")
                    {
                        fresh_count.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });

        assert_eq!(
            fresh_count.load(Ordering::SeqCst),
            1,
            "exactly one caller may observe the assertion as unseen"
        );
    }

    use std::time::{Duration, UNIX_EPOCH};

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
        let expires_at = future_expiry(300);
        let inserted = cache
            .check_and_insert(
                &[ReplayEntry::assertion("_a1", expires_at)],
                SystemTime::now(),
            )
            .expect("first insert");
        assert!(inserted, "first insert returns true");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_duplicate_within_ttl_rejected() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let expires_at = future_expiry(300);
        let first = cache
            .check_and_insert(
                &[ReplayEntry::assertion("_a1", expires_at)],
                SystemTime::now(),
            )
            .expect("first insert");
        assert!(first);
        let second = cache
            .check_and_insert(
                &[ReplayEntry::assertion("_a1", expires_at)],
                SystemTime::now(),
            )
            .expect("second insert");
        assert!(!second, "duplicate within TTL returns false");
        // Cache still holds exactly one entry — we didn't accidentally
        // double-insert.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn conflicting_batch_inserts_nothing() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let expires_at = future_expiry(300);
        let now = SystemTime::now();
        assert!(
            cache
                .check_and_insert(&[ReplayEntry::assertion("_existing", expires_at)], now)
                .expect("seed existing entry")
        );

        assert!(
            !cache
                .check_and_insert(
                    &[
                        ReplayEntry::assertion("_existing", expires_at),
                        ReplayEntry::proxy_transaction("_new", expires_at),
                    ],
                    now,
                )
                .expect("conflicting batch")
        );
        assert_eq!(cache.len(), 1, "the fresh batch member was not inserted");
        assert!(
            cache
                .check_and_insert(&[ReplayEntry::proxy_transaction("_new", expires_at)], now,)
                .expect("fresh member remains insertable")
        );
    }

    #[test]
    fn over_capacity_batch_inserts_nothing() {
        let cache = InMemoryReplayCache::new(1);
        let expires_at = future_expiry(300);
        let now = SystemTime::now();
        let err = cache
            .check_and_insert(
                &[
                    ReplayEntry::assertion("_assertion", expires_at),
                    ReplayEntry::proxy_transaction("_transaction", expires_at),
                ],
                now,
            )
            .expect_err("two entries cannot fit in a capacity-one cache");
        assert!(matches!(err, Error::ReplayCacheFull), "got {err:?}");
        assert!(
            cache.is_empty(),
            "capacity failure must not partially commit"
        );
        assert!(
            cache
                .check_and_insert(&[ReplayEntry::assertion("_assertion", expires_at)], now)
                .expect("single entry still fits")
        );
    }

    #[test]
    fn duplicate_key_within_batch_inserts_nothing() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let expires_at = future_expiry(300);
        let now = SystemTime::now();
        let duplicate = ReplayEntry::assertion("_same", expires_at);

        assert!(
            !cache
                .check_and_insert(&[duplicate, duplicate], now)
                .expect("duplicate batch is a conflict")
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn namespaces_do_not_collide() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let expires_at = future_expiry(300);
        let now = SystemTime::now();

        assert!(
            cache
                .check_and_insert(&[ReplayEntry::assertion("same", expires_at)], now)
                .expect("assertion insert")
        );
        assert!(
            cache
                .check_and_insert(&[ReplayEntry::proxy_transaction("same", expires_at)], now,)
                .expect("transaction insert")
        );
    }

    #[test]
    fn supplied_clock_controls_eviction() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let validation_now = UNIX_EPOCH + Duration::from_secs(100);
        let expires_at = validation_now + Duration::from_mins(1);
        let entry = ReplayEntry::assertion("_clocked", expires_at);

        assert!(
            cache
                .check_and_insert(&[entry], validation_now)
                .expect("first insert")
        );
        assert!(
            !cache
                .check_and_insert(&[entry], validation_now)
                .expect("same supplied time still observes tombstone"),
            "wall-clock time must not evict a tombstone validated under the supplied clock"
        );
        assert!(
            cache
                .check_and_insert(&[entry], expires_at)
                .expect("entry is reusable only once supplied time reaches expiry")
        );
    }

    #[test]
    fn replay_after_expiry_succeeds() {
        // We can't move the wall clock backward, so use a past
        // `expires_at` to simulate an entry that has already aged out.
        // The lazy sweep on the next call should drop it, after which
        // the same id can be inserted again.
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let expired_at = past_expiry(1);
        let inserted = cache
            .check_and_insert(
                &[ReplayEntry::assertion("_a1", expired_at)],
                SystemTime::now(),
            )
            .expect("insert with past expiry");
        assert!(inserted);
        // First call already inserted the entry. Any subsequent call
        // will sweep it because its `expires_at` is in the past.
        let expires_at = future_expiry(300);
        let again = cache
            .check_and_insert(
                &[ReplayEntry::assertion("_a1", expires_at)],
                SystemTime::now(),
            )
            .expect("re-insert after expiry");
        assert!(
            again,
            "an entry whose expires_at is in the past must be swept and re-insertable"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn poisoned_lock_fails_closed_instead_of_panicking() {
        // The only remaining uncovered branch in this module, and the one that
        // matters most: if the mutex is poisoned the cache must surface an
        // error, never panic and never quietly report an assertion as fresh.
        // A panic here would take down the request handler; a false `true`
        // would wave a replay through.
        let cache = InMemoryReplayCache::default();

        // Poison the lock by panicking while holding it. The default hook is
        // muted so the deliberate panic does not look like a test failure.
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_info| {}));
        let outcome = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = cache.inner.lock().expect("uncontended first lock");
                    panic!("deliberately poisoning the replay cache lock");
                })
                .join()
        });
        std::panic::set_hook(previous_hook);
        assert!(outcome.is_err(), "the spawned thread must have panicked");

        let err = cache
            .check_and_insert(
                &[ReplayEntry::assertion(
                    "_a1",
                    UNIX_EPOCH + Duration::from_secs(1),
                )],
                UNIX_EPOCH,
            )
            .expect_err("a poisoned lock must surface as an error");
        assert!(matches!(
            err,
            Error::ReplayCache { reason } if reason == "in-memory replay cache mutex poisoned"
        ));
    }

    #[test]
    fn replay_capacity_full_errors() {
        let cache = InMemoryReplayCache::new(2);
        let expires_at = future_expiry(300);
        let now = SystemTime::now();
        cache
            .check_and_insert(&[ReplayEntry::assertion("_a", expires_at)], now)
            .expect("first");
        cache
            .check_and_insert(&[ReplayEntry::assertion("_b", expires_at)], now)
            .expect("second");
        let err = cache
            .check_and_insert(&[ReplayEntry::assertion("_c", expires_at)], now)
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
        let expires_at = future_expiry(300);
        cache
            .check_and_insert(
                &[ReplayEntry::assertion("_a", expires_at)],
                SystemTime::now(),
            )
            .expect("default cache accepts inserts");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_mode_default_is_strict() {
        // Strict is the safe default. Callers who don't reach for the knob
        // get the same behavior as before `ReplayMode` existed.
        assert_eq!(ReplayMode::default(), ReplayMode::All);
    }

    /// The trait must be object-safe; `ConsumeResponse::replay_cache`
    /// stores a `&dyn ReplayCache`, so this is load-bearing.
    #[test]
    fn replay_cache_is_object_safe() {
        let cache = InMemoryReplayCache::new(TEST_CAPACITY);
        let as_dyn: &dyn ReplayCache = &cache;
        let expires_at = future_expiry(60);
        as_dyn
            .check_and_insert(
                &[ReplayEntry::assertion("_a", expires_at)],
                SystemTime::now(),
            )
            .expect("dyn dispatch works");
    }
}
