//! Bounded, TTL-fresh cache fronting the session store (A3).
//!
//! Two clocks, on purpose:
//! - session expiry reads wall-clock (`expires_at` is a DB timestamp).
//! - cache *freshness* uses a monotonic [`Instant`], so a wall-clock step can't
//!   silently stretch the re-validation window.
//!
//! Why a freshness TTL: [`super::SessionStore::revoke`] only tombstones the
//! entry on the replica that handled the logout. Under HA (multiple replicas
//! behind a load balancer — see `website/docs/initial-idea/02-architecture.md#ha`)
//! a session revoked on replica B stays cached on replica A until A's entry ages
//! out. The TTL caps that window: after `ttl`, A's next lookup re-reads the
//! state DB and honors `revoked_at`.
//!
//! Tombstones: a revoke (or a DB read that finds the session inactive) leaves a
//! negative entry that [`SessionCache::insert`] refuses to overwrite. That
//! closes the race where a lookup reads the row just before a concurrent revoke
//! commits and would otherwise re-cache the now-revoked session for a full TTL.
//! A revoked/expired/missing session never becomes valid again, so a tombstone
//! can't wrongly reject anyone.
//!
//! Bounded growth: a full cache stops admitting new live entries (the lookup
//! still succeeds from the DB) instead of scanning the map under the write
//! lock; the GC task's [`SessionCache::sweep`] reclaims stale entries.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, RwLock};

use super::session::{Identity, SessionId};

/// Freshness window default. Short — revocation is security-critical
/// (off-boarding, leaked bearer), so re-validate more eagerly than the 60s
/// permissions-grant cache. Cross-replica revocation propagates within this
/// bound while the request path stays off the state DB the rest of the time.
pub const DEFAULT_SESSION_CACHE_TTL_SECONDS: u64 = 30;

/// Hard ceiling on cached live sessions. ~100k entries at a few hundred bytes
/// each caps the cache in the tens of MB even under pathological login churn.
/// Not an operator knob — a memory backstop, not a policy.
const DEFAULT_SESSION_CACHE_MAX_ENTRIES: usize = 100_000;

/// Floor on a tombstone's lifetime. Covers a lookup whose DB read is still in
/// flight when the revoke lands, even when the freshness TTL is zero.
const MIN_TOMBSTONE_LIFETIME: Duration = Duration::from_secs(60);

/// Tuning for [`SessionCache`]. `Default` is production-safe; the test-facing
/// `SessionStore::new` uses it as-is, production overrides `ttl` from config.
#[derive(Debug, Clone, Copy)]
pub struct SessionCacheConfig {
    /// A cache hit older than this re-reads the state DB. `0` re-validates
    /// every request (no effective caching).
    pub ttl: Duration,
    /// Hard cap on cached live entries; a full cache stops admitting new ones.
    pub max_entries: usize,
}

impl Default for SessionCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(DEFAULT_SESSION_CACHE_TTL_SECONDS),
            max_entries: DEFAULT_SESSION_CACHE_MAX_ENTRIES,
        }
    }
}

#[derive(Debug)]
enum Entry {
    Live {
        identity: Arc<Identity>,
        expires_at: DateTime<Utc>,
        /// Monotonic stamp of when this entry was last validated against the DB.
        cached_at: Instant,
    },
    Tombstone {
        until: Instant,
        reason: Inactive,
    },
}

/// Why a session can no longer authenticate. None of these ever reverts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inactive {
    Revoked,
    Expired,
    /// No row: never issued here, or already garbage-collected.
    Unknown,
}

/// What the cache knows about a session id.
#[derive(Debug)]
pub enum Cached {
    /// Fresh and active: serve without touching the DB.
    Live(Arc<Identity>),
    /// Known inactive — reject without touching the DB.
    Gone(Inactive),
    /// Absent or stale: re-read the DB.
    Miss,
}

/// In-memory session cache with a freshness TTL, revocation tombstones and a
/// hard size cap on live entries.
#[derive(Debug)]
pub struct SessionCache {
    ttl: Duration,
    tombstone_lifetime: Duration,
    max_entries: usize,
    inner: RwLock<HashMap<SessionId, Entry>>,
    /// One DB read per session id at a time; see [`SessionCache::flight`].
    flights: Mutex<HashMap<SessionId, Arc<Mutex<()>>>>,
}

impl SessionCache {
    pub fn new(config: SessionCacheConfig) -> Self {
        Self {
            ttl: config.ttl,
            tombstone_lifetime: config.ttl.max(MIN_TOMBSTONE_LIFETIME),
            // 0 would refuse every entry; clamp to a sane floor.
            max_entries: config.max_entries.max(1),
            inner: RwLock::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get(&self, id: SessionId, now: DateTime<Utc>) -> Cached {
        let map = self.inner.read().await;
        match map.get(&id) {
            None => Cached::Miss,
            Some(Entry::Tombstone { until, reason }) if Instant::now() < *until => {
                Cached::Gone(*reason)
            }
            Some(Entry::Tombstone { .. }) => Cached::Miss,
            Some(Entry::Live { expires_at, .. }) if *expires_at <= now => {
                Cached::Gone(Inactive::Expired)
            }
            Some(Entry::Live {
                identity,
                cached_at,
                ..
            }) if cached_at.elapsed() < self.ttl => Cached::Live(Arc::clone(identity)),
            Some(Entry::Live { .. }) => Cached::Miss,
        }
    }

    /// Cache an active session. Refused when a live tombstone holds the id (a
    /// revoke raced this lookup) or when the cache is full of other entries.
    pub async fn insert(&self, identity: Identity, expires_at: DateTime<Utc>) {
        let id = identity.session_id;
        let mut map = self.inner.write().await;
        match map.get(&id) {
            Some(Entry::Tombstone { until, .. }) if Instant::now() < *until => return,
            Some(_) => {}
            None if map.len() >= self.max_entries => {
                tracing::debug!("session cache at capacity; serving uncached");
                return;
            }
            None => {}
        }
        map.insert(
            id,
            Entry::Live {
                identity: Arc::new(identity),
                expires_at,
                cached_at: Instant::now(),
            },
        );
    }

    /// Remember that `id` is inactive. Ignores the size cap: tombstones are
    /// bounded by the revoke rate, and dropping one would reopen the race.
    pub async fn tombstone(&self, id: SessionId, reason: Inactive) {
        let until = Instant::now() + self.tombstone_lifetime;
        self.inner
            .write()
            .await
            .insert(id, Entry::Tombstone { until, reason });
    }

    /// Drop stale live entries and lapsed tombstones. Called by the GC task.
    pub async fn sweep(&self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.inner.write().await.retain(|_, entry| match entry {
            Entry::Live { cached_at, .. } => cached_at.elapsed() < ttl,
            Entry::Tombstone { until, .. } => now < *until,
        });
    }

    /// The per-id lock a DB read holds, so concurrent misses for one session
    /// issue one query: followers wait, then re-check the cache. Pair with
    /// [`SessionCache::end_flight`].
    pub async fn flight(&self, id: SessionId) -> Arc<Mutex<()>> {
        Arc::clone(self.flights.lock().await.entry(id).or_default())
    }

    /// Forget the flight lock for `id`. Waiters still holding a clone proceed
    /// and find the cache filled; a newcomer starts a fresh flight.
    pub async fn end_flight(&self, id: SessionId) {
        self.flights.lock().await.remove(&id);
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[cfg(test)]
#[path = "session_cache_tests.rs"]
mod tests;
