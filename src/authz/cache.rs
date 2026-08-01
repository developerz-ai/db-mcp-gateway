//! Per-`user_sub` TTL cache for the DB-grant loader (#49).
//!
//! Hot path: `get_for(identity)` returns the cached `Arc<Vec<Grant>>` without
//! a DB round-trip when the entry is fresh. Cold path loads via
//! [`super::loader::load_db_grants_for`] and inserts.
//!
//! Invalidation: admin API writes (#52–#54) call [`PermissionsCache::invalidate`]
//! immediately after a successful write, so the staleness window for an
//! observed revoke is the in-flight request, not the TTL. The TTL is the
//! safety net for missed invalidations (process restart, batch tools that
//! mutate the DB directly).
//!
//! Concurrency: `tokio::sync::RwLock` per CLAUDE.md — never `std::sync` on
//! the request path. A read lock guards the fast path; writes briefly take
//! an exclusive lock. Two concurrent cold-path loads for the same user are
//! tolerated (last write wins, both produce equivalent grant sets), so we
//! don't bother with a per-user singleflight.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::auth::Identity;
use crate::config::Grant;
use crate::state::permissions::PermissionsRepo;

use super::loader::{LoadError, load_db_grants_for};

#[derive(Debug, Clone)]
struct CacheEntry {
    loaded_at: Instant,
    grants: Arc<Vec<Grant>>,
}

#[derive(Clone)]
pub struct PermissionsCache {
    repo: Arc<dyn PermissionsRepo>,
    ttl: Duration,
    inner: Arc<RwLock<HashMap<String, CacheEntry>>>,
    revision: Arc<AtomicU64>,
}

impl std::fmt::Debug for PermissionsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermissionsCache")
            .field("ttl", &self.ttl)
            // Don't recurse into the repo (Arc<dyn _>) or hold the RwLock for
            // a Debug call — Debug must be cheap and infallible.
            .finish_non_exhaustive()
    }
}

impl PermissionsCache {
    pub fn new(repo: Arc<dyn PermissionsRepo>, ttl: Duration) -> Self {
        Self {
            repo,
            ttl,
            inner: Arc::new(RwLock::new(HashMap::new())),
            revision: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Return the live DB-grant set for `identity`. Loads on cache miss or
    /// expiry. Fail-closed: a load error propagates — callers MUST treat
    /// the request as Deny (audit + return forbidden), never fall through
    /// to YAML-only.
    ///
    /// Uses a revision guard to prevent the invalidate/load race: if an
    /// invalidation occurs between the load and insert, we retry to ensure
    /// fresh data is cached.
    pub async fn get_for(&self, identity: &Identity) -> Result<Arc<Vec<Grant>>, LoadError> {
        {
            let map = self.inner.read().await;
            if let Some(entry) = map.get(&identity.user_sub) {
                if entry.loaded_at.elapsed() < self.ttl {
                    return Ok(entry.grants.clone());
                }
            }
        }
        loop {
            let rev_before = self.revision.load(Ordering::Acquire);
            let grants = load_db_grants_for(self.repo.as_ref(), identity).await?;
            // If the revision changed during the load, an invalidation occurred.
            // Retry to ensure we insert fresh data.
            if self.revision.load(Ordering::Acquire) != rev_before {
                continue;
            }
            let arc = Arc::new(grants);
            let mut map = self.inner.write().await;
            // Double-check before inserting; another invalidation may have
            // occurred after we released the read lock above.
            if self.revision.load(Ordering::Acquire) == rev_before {
                map.insert(
                    identity.user_sub.clone(),
                    CacheEntry {
                        loaded_at: Instant::now(),
                        grants: arc.clone(),
                    },
                );
                return Ok(arc);
            }
            // Revision changed again; drop the lock and retry.
        }
    }

    /// Drop the entry for `user_sub`. Admin API writes that touch this user's
    /// grants (or the user/database rows the grants reference) must call this
    /// so the next request reloads from the DB. Idempotent — a missing entry
    /// is a no-op.
    pub async fn invalidate(&self, user_sub: &str) {
        self.revision.fetch_add(1, Ordering::AcqRel);
        let mut map = self.inner.write().await;
        map.remove(user_sub);
    }

    /// Drop every cached entry. Used by admin endpoints that mutate a
    /// `permissions_databases` row (which can change the meaning of every
    /// user's wildcard grants) — narrower per-user invalidation isn't
    /// sufficient. Cheap; the next request for each user simply reloads.
    pub async fn invalidate_all(&self) {
        self.revision.fetch_add(1, Ordering::AcqRel);
        let mut map = self.inner.write().await;
        map.clear();
    }

    /// Fire-and-forget per-user invalidation. Runs AFTER the caller's tx has
    /// committed so a rolled-back write never bumps the resolver revision.
    /// Cheap no-op when the cache is disabled (YAML-only installs) or the
    /// caller didn't have a `user_sub` to key on.
    ///
    /// Detached via `tokio::spawn` so a client disconnect between the
    /// revision bump and the entry removal cannot leave the stale entry live
    /// until TTL: [`PermissionsCache::invalidate`] takes a write lock, and
    /// awaiting it on the request task means cancellation drops the future
    /// mid-invalidate. The spawned task owns its inputs and runs to
    /// completion regardless.
    ///
    /// Single canonical detach point for every admin write path (users,
    /// grants) so the detach contract lives next to the lock it protects.
    pub fn spawn_invalidate(cache: &Option<Self>, user_sub: Option<&str>) {
        if let (Some(cache), Some(sub)) = (cache.as_ref(), user_sub) {
            let cache = cache.clone();
            let sub = sub.to_string();
            tokio::spawn(async move {
                cache.invalidate(&sub).await;
            });
        }
    }

    /// Fire-and-forget full flush. Same detach contract as
    /// [`Self::spawn_invalidate`], but calls [`Self::invalidate_all`] because
    /// the mutation (a `permissions_databases` row change) can affect any
    /// user's grant set — narrower per-user invalidation isn't enough.
    pub fn spawn_invalidate_all(cache: &Option<Self>) {
        if let Some(cache) = cache.as_ref() {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache.invalidate_all().await;
            });
        }
    }
}

/// Helper for the tool layer: load this identity's DB grants if the cache is
/// wired (production), or return an empty slice (tests with no state DB).
/// Tools should propagate `Err` as an `internal` outcome — fail-closed never
/// silently degrades to YAML-only.
pub async fn load_or_empty(
    cache: Option<&PermissionsCache>,
    identity: &Identity,
) -> Result<Arc<Vec<Grant>>, LoadError> {
    match cache {
        Some(c) => c.get_for(identity).await,
        None => Ok(Arc::new(Vec::new())),
    }
}
