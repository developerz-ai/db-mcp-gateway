//! Per-`user_sub` TTL cache for the DB-grant loader (#49).
//!
//! Hot path: [`PermissionsCache::get_for`] returns the cached grant set with
//! no DB round trip while the entry is fresh. Cold path: one load per subject
//! at a time (single flight), cached only if no invalidation of that subject
//! landed while it ran (per-subject revision).
//!
//! Invalidation: an admin commit applies its [`PermissionsChange`] here and
//! `NOTIFY`s every other replica, which applies it too. The TTL bounds what
//! nothing announces — a lost listener connection, or a MySQL store filled
//! by external tooling.
//!
//! Concurrency: `tokio::sync` only. The map lock is held for map edits,
//! never across a load; the per-subject flight lock is held across exactly
//! one load.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};

use crate::audit::drain::DetachedTasks;
use crate::auth::{Identity, IdentityKind};
use crate::config::Grant;
use crate::state::permissions::{PermissionsChange, PermissionsRepo};

use super::loader::{LoadError, load_db_grants_for};

/// Loads attempted per cold miss before the newest result is returned
/// uncached. Each retry means an invalidation of this subject landed
/// mid-load; churn that persistent must not pin a request in a loop.
const MAX_LOAD_ATTEMPTS: u32 = 3;

#[derive(Debug, Default)]
struct Slot {
    /// Bumped by every invalidation of this subject. A load that started on
    /// an older revision may predate the change, so it is not cached.
    revision: u64,
    entry: Option<CacheEntry>,
    flight: Arc<Mutex<()>>,
}

#[derive(Debug)]
struct CacheEntry {
    loaded_at: Instant,
    grants: Arc<Vec<Grant>>,
}

#[derive(Clone)]
pub struct PermissionsCache {
    repo: Arc<dyn PermissionsRepo>,
    ttl: Duration,
    slots: Arc<RwLock<HashMap<String, Slot>>>,
    detached: DetachedTasks,
}

impl std::fmt::Debug for PermissionsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug must be cheap and infallible: no lock, no repo recursion.
        f.debug_struct("PermissionsCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl PermissionsCache {
    pub fn new(repo: Arc<dyn PermissionsRepo>, ttl: Duration) -> Self {
        Self {
            repo,
            ttl,
            slots: Arc::new(RwLock::new(HashMap::new())),
            detached: DetachedTasks::new(),
        }
    }

    /// Track [`Self::spawn_apply`] work in the app's shared set, so the
    /// shutdown drain waits for in-flight invalidations.
    pub fn with_detached(mut self, detached: DetachedTasks) -> Self {
        self.detached = detached;
        self
    }

    /// The live DB-grant set for `identity`. Fail-closed: a load error
    /// propagates and callers MUST deny, never fall through to YAML-only.
    ///
    /// A service identity's authority is exactly its YAML group (spec 14),
    /// so it never reads the store — a DB grant seeded for `service:<name>`
    /// is inert.
    pub async fn get_for(&self, identity: &Identity) -> Result<Arc<Vec<Grant>>, LoadError> {
        if identity.kind == IdentityKind::Service {
            return Ok(Arc::new(Vec::new()));
        }
        let sub = identity.user_sub.as_str();
        if let Some(hit) = self.fresh(sub).await {
            return Ok(hit);
        }
        let flight = self.flight_for(sub).await;
        let _flight = flight.lock().await;
        // The flight we queued behind may have filled the entry.
        if let Some(hit) = self.fresh(sub).await {
            return Ok(hit);
        }
        let mut attempt = 1;
        loop {
            let revision = self.revision(sub).await;
            let grants = Arc::new(load_db_grants_for(self.repo.as_ref(), sub).await?);
            // Out of attempts: the load ran concurrently with the writes that
            // kept invalidating it, so serving it uncached is as current as
            // this request can be ordered — caching it would not be.
            if self.insert_if_current(sub, revision, &grants).await || attempt == MAX_LOAD_ATTEMPTS
            {
                return Ok(grants);
            }
            attempt += 1;
        }
    }

    /// Apply a committed change: drop the entries it can have affected.
    pub async fn apply(&self, change: &PermissionsChange) {
        let mut slots = self.slots.write().await;
        match change {
            PermissionsChange::User(sub) => {
                if let Some(slot) = slots.get_mut(sub) {
                    invalidate(slot);
                }
            }
            PermissionsChange::All => slots.values_mut().for_each(invalidate),
        }
    }

    /// [`Self::apply`] on a detached, drain-tracked task. An admin handler
    /// calls this after commit; detaching means a client disconnect cannot
    /// drop the future between commit and invalidation and leave a stale
    /// entry until TTL.
    pub fn spawn_apply(&self, change: PermissionsChange) {
        let cache = self.clone();
        self.detached
            .spawn(async move { cache.apply(&change).await });
    }

    async fn fresh(&self, sub: &str) -> Option<Arc<Vec<Grant>>> {
        let slots = self.slots.read().await;
        let entry = slots.get(sub)?.entry.as_ref()?;
        (entry.loaded_at.elapsed() < self.ttl).then(|| entry.grants.clone())
    }

    async fn flight_for(&self, sub: &str) -> Arc<Mutex<()>> {
        let mut slots = self.slots.write().await;
        slots.entry(sub.to_string()).or_default().flight.clone()
    }

    /// The slot exists for as long as the caller holds its flight lock: the
    /// sweep keeps every slot whose flight is shared.
    async fn revision(&self, sub: &str) -> u64 {
        let slots = self.slots.read().await;
        slots.get(sub).map_or(0, |slot| slot.revision)
    }

    /// Cache `grants` unless `sub` was invalidated since `revision` was read;
    /// sweep expired idle slots on the way out.
    async fn insert_if_current(&self, sub: &str, revision: u64, grants: &Arc<Vec<Grant>>) -> bool {
        let mut slots = self.slots.write().await;
        let Some(slot) = slots.get_mut(sub) else {
            return false;
        };
        if slot.revision != revision {
            return false;
        }
        slot.entry = Some(CacheEntry {
            loaded_at: Instant::now(),
            grants: grants.clone(),
        });
        let ttl = self.ttl;
        slots.retain(|_, slot| {
            Arc::strong_count(&slot.flight) > 1
                || slot
                    .entry
                    .as_ref()
                    .is_some_and(|e| e.loaded_at.elapsed() < ttl)
        });
        true
    }

    #[cfg(test)]
    async fn slot_count(&self) -> usize {
        self.slots.read().await.len()
    }
}

fn invalidate(slot: &mut Slot) {
    slot.revision += 1;
    slot.entry = None;
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
