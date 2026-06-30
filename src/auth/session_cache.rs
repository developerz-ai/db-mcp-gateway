//! Bounded, TTL-fresh cache fronting the session store (A3).
//!
//! Two clocks, on purpose:
//! - [`Session::is_active`] reads wall-clock (`expires_at` / `revoked_at` are
//!   DB timestamps).
//! - cache *freshness* uses a monotonic [`Instant`], so a wall-clock step can't
//!   silently stretch the re-validation window.
//!
//! Why a freshness TTL: [`super::SessionStore::revoke`] only evicts the entry
//! on the replica that handled the logout. Under HA (multiple replicas behind a
//! load balancer — see `docs/initial-idea/02-architecture.md#ha`) a session
//! revoked on replica B stays cached on replica A until A's entry ages out. The
//! TTL caps that window: after `ttl`, A's next lookup re-reads the state DB and
//! honors `revoked_at`. Single-replica deployments still observe revocation on
//! the very next request (revoke evicts locally); the TTL is the multi-replica
//! safety net, not the primary mechanism.
//!
//! Bounded growth: legitimate login churn keeps inserting fresh ids (DB misses
//! never get cached — `lookup` removes them). `max_entries` is a hard ceiling;
//! a full cache first drops entries already past their freshness TTL (re-reading
//! those is free), then evicts the oldest if the sweep freed nothing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use super::session::{Session, SessionId};

/// Freshness window default. Short — revocation is security-critical
/// (off-boarding, leaked bearer), so re-validate more eagerly than the 60s
/// permissions-grant cache. Cross-replica revocation propagates within this
/// bound while the request path stays off the state DB the rest of the time.
pub const DEFAULT_SESSION_CACHE_TTL_SECONDS: u64 = 30;

/// Hard ceiling on cached sessions. ~100k entries at a few hundred bytes each
/// caps the cache in the tens of MB even under pathological login churn. Not an
/// operator knob — a memory backstop, not a policy.
const DEFAULT_SESSION_CACHE_MAX_ENTRIES: usize = 100_000;

/// Tuning for [`SessionCache`]. `Default` is production-safe; the test-facing
/// `SessionStore::new` uses it as-is, production overrides `ttl` from config.
#[derive(Debug, Clone, Copy)]
pub struct SessionCacheConfig {
    /// A cache hit older than this re-reads the state DB. `0` re-validates
    /// every request (no effective caching).
    pub ttl: Duration,
    /// Hard cap on cached entries; a full cache evicts before admitting a new
    /// one.
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

struct CacheEntry {
    session: Session,
    /// Monotonic stamp of when this entry was last validated against the DB.
    cached_at: Instant,
}

/// In-memory session cache with a freshness TTL and a hard size cap.
pub struct SessionCache {
    ttl: Duration,
    max_entries: usize,
    inner: RwLock<HashMap<SessionId, CacheEntry>>,
}

impl SessionCache {
    pub fn new(config: SessionCacheConfig) -> Self {
        Self {
            ttl: config.ttl,
            // 0 would make every insert evict-then-insert; clamp to a sane floor.
            max_entries: config.max_entries.max(1),
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Return the cached session only if it is both *fresh* (validated within
    /// `ttl`) and *active* at `now`. A stale or absent entry returns `None`,
    /// forcing the caller to re-read the state DB — that re-read is what makes a
    /// revoke on another replica take effect within `ttl`.
    pub async fn get(&self, id: SessionId, now: DateTime<Utc>) -> Option<Session> {
        let map = self.inner.read().await;
        let entry = map.get(&id)?;
        // Stale → miss (re-validate); inactive can't normally be cached, but a
        // wall-clock-expired entry is rejected here belt-and-suspenders.
        if entry.cached_at.elapsed() >= self.ttl || !entry.session.is_active(now) {
            return None;
        }
        Some(entry.session.clone())
    }

    /// Insert (or refresh) an entry, enforcing the size cap first.
    pub async fn insert(&self, id: SessionId, session: Session) {
        let entry = CacheEntry {
            session,
            cached_at: Instant::now(),
        };
        let mut map = self.inner.write().await;
        if map.len() >= self.max_entries && !map.contains_key(&id) {
            evict_one(&mut map, self.ttl);
        }
        map.insert(id, entry);
    }

    /// Drop an entry. Idempotent; a missing id is a no-op.
    pub async fn remove(&self, id: SessionId) {
        self.inner.write().await.remove(&id);
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

/// Free one slot in a full map. Drops every entry already past `ttl` first —
/// those force a DB re-read on next lookup anyway, so eviction is free — and
/// falls back to evicting the single oldest entry if nothing was stale.
fn evict_one(map: &mut HashMap<SessionId, CacheEntry>, ttl: Duration) {
    let before = map.len();
    map.retain(|_, e| e.cached_at.elapsed() < ttl);
    if map.len() < before {
        return;
    }
    if let Some(oldest) = map
        .iter()
        .min_by_key(|(_, e)| e.cached_at)
        .map(|(id, _)| *id)
    {
        // All entries fresh and the cache is full: capacity is undersized for
        // the live-session count. Evict the oldest (closest to re-validation).
        tracing::debug!("session cache at capacity; evicting oldest entry");
        map.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn session(active_for_secs: i64) -> Session {
        let now = Utc::now();
        Session {
            id: SessionId::new(),
            user_sub: "sub".into(),
            user_email: "e@example.com".into(),
            groups: vec!["g".into()],
            agent_client: None,
            expires_at: now + ChronoDuration::seconds(active_for_secs),
            revoked_at: None,
        }
    }

    fn cache(ttl_secs: u64, max_entries: usize) -> SessionCache {
        SessionCache::new(SessionCacheConfig {
            ttl: Duration::from_secs(ttl_secs),
            max_entries,
        })
    }

    #[tokio::test]
    async fn fresh_active_session_is_returned() {
        let cache = cache(3600, 16);
        let s = session(3600);
        cache.insert(s.id, s.clone()).await;
        assert!(cache.get(s.id, Utc::now()).await.is_some());
    }

    #[tokio::test]
    async fn absent_session_is_a_miss() {
        let cache = cache(3600, 16);
        assert!(cache.get(SessionId::new(), Utc::now()).await.is_none());
    }

    #[tokio::test]
    async fn stale_entry_forces_revalidation() {
        // ttl = 0 → every entry is instantly stale, so `get` always misses and
        // the caller is forced back to the DB. This is the cross-replica
        // revocation safety net at its extreme.
        let cache = cache(0, 16);
        let s = session(3600);
        cache.insert(s.id, s.clone()).await;
        assert!(cache.get(s.id, Utc::now()).await.is_none());
    }

    #[tokio::test]
    async fn expired_session_is_not_returned() {
        // Fresh in the cache, but wall-clock-expired → `is_active` rejects it.
        let cache = cache(3600, 16);
        let s = session(-1);
        cache.insert(s.id, s.clone()).await;
        assert!(cache.get(s.id, Utc::now()).await.is_none());
    }

    #[tokio::test]
    async fn eviction_keeps_cache_within_capacity() {
        let cache = cache(3600, 2);
        let (a, b, c) = (session(3600), session(3600), session(3600));
        cache.insert(a.id, a.clone()).await;
        cache.insert(b.id, b.clone()).await;
        cache.insert(c.id, c.clone()).await;

        assert_eq!(cache.len().await, 2, "size cap is hard");
        // All entries were fresh, so the oldest (a) is evicted; the newest stays.
        assert!(
            cache.get(a.id, Utc::now()).await.is_none(),
            "oldest evicted"
        );
        assert!(
            cache.get(c.id, Utc::now()).await.is_some(),
            "newest retained"
        );
    }

    #[tokio::test]
    async fn stale_sweep_reclaims_capacity_before_eviction() {
        // ttl = 0 → on the over-capacity insert, the stale sweep clears the map
        // for free, so no oldest-eviction min-scan is needed.
        let cache = cache(0, 2);
        let (a, b, c) = (session(3600), session(3600), session(3600));
        cache.insert(a.id, a.clone()).await;
        cache.insert(b.id, b.clone()).await;
        cache.insert(c.id, c.clone()).await;
        assert_eq!(cache.len().await, 1, "stale sweep cleared room");
    }

    #[tokio::test]
    async fn zero_capacity_is_clamped_to_one() {
        let cache = cache(3600, 0);
        let s = session(3600);
        cache.insert(s.id, s.clone()).await;
        assert_eq!(cache.len().await, 1);
    }
}
