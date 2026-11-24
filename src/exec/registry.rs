//! [`AdapterRegistry`]: one lazily-opened adapter per `(server, database)`
//! and config snapshot, replaced when it goes stale and not re-opened while
//! its target is down.

mod fingerprint;
mod slot;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::hash::RandomState;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::audit::drain::DetachedTasks;
use crate::config::{Database, Server, ServerKind};

use super::adapter::{DbAdapter, ExecError};
use super::mongo::MongoAdapter;
use super::pg::PgAdapter;
use super::pool_sizing::PoolSizing;
use super::redis::RedisAdapter;
use fingerprint::Fingerprint;
use slot::Slot;

/// How long a failed open is remembered. Opening a dead target costs up to
/// the pool acquire timeout; without this every request to it would pay that
/// again while holding a global request permit.
const FAILED_OPEN_TTL: Duration = Duration::from_secs(5);

/// How long a slot opened from other settings outlives its last lookup. A
/// request carries its config snapshot for at most `transport::MCP_TIMEOUT`,
/// so past this no straggler from before a reload can still ask for it.
const SNAPSHOT_LIFETIME: Duration = Duration::from_secs(300);

/// Composite key for the registry: `(server.name, database.name)`.
type AdapterKey = (String, String);
/// One slot per config fingerprint seen for the key. Normally one; a reload
/// briefly leaves the pre-reload snapshot's slot beside the new one.
type AdapterMap = HashMap<AdapterKey, Vec<Arc<Slot>>>;

/// Per-`(server, database)` adapter registry. Hands out `Arc<dyn DbAdapter>`
/// keyed on `(server.name, database.name)` so a slow query on DB A can never
/// block DB B (each adapter owns its own pool).
///
/// Dispatch is on `server.kind`: `Postgres`, `Mongo` and `Redis` are wired; the
/// remaining `ServerKind` variants return `ExecError::UnsupportedAdapter`.
/// `ServerKind::has_adapter` is the shared source of truth — config
/// validation rejects unwired kinds at boot, so that arm is a backstop a
/// validated config never reaches.
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    inner: Arc<RwLock<AdapterMap>>,
    /// Handed to every adapter for its detached cancels.
    detached: DetachedTasks,
    /// Keys every slot's [`Fingerprint`]; shared by clones.
    fingerprint_keys: RandomState,
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Adapter `Debug` impls already redact connection strings; print
        // structural info only in case a future impl regresses.
        f.debug_struct("AdapterRegistry")
            .field("adapters", &"<RwLock<HashMap<(server, db), Vec<Slot>>>>")
            .finish()
    }
}

impl AdapterRegistry {
    /// A registry whose detached cancels are tracked by a set of its own —
    /// for callers that never drain (tests, tools run in isolation).
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry whose detached cancels join `detached`, the set the
    /// process drains at shutdown.
    pub fn with_detached(detached: DetachedTasks) -> Self {
        Self {
            detached,
            ..Self::default()
        }
    }

    /// Returns the adapter for `(server.name, database.name)`, opening it if
    /// needed. Lazy: a misconfigured DB only errors on first use, not at
    /// boot. A stale adapter (the target rejected its credentials) is
    /// replaced, so a rotated password is picked up without a restart.
    ///
    /// No lock guard is alive across the open, so a database that hangs its
    /// connect delays only callers of that same key.
    pub async fn get_or_open(
        &self,
        server: &Server,
        database: &Database,
    ) -> Result<Arc<dyn DbAdapter>, ExecError> {
        let key = (server.name.clone(), database.name.clone());
        let fingerprint = Fingerprint::of(&self.fingerprint_keys, server, database);
        loop {
            let slot = self.slot(&key, fingerprint).await;
            match slot.adapter.get() {
                Some(adapter) if !adapter.is_stale() => return Ok(Arc::clone(adapter)),
                Some(_) => {
                    self.evict_slot(&key, &slot).await;
                    continue;
                }
                None => {}
            }

            if slot.recently_failed().await {
                return Err(ExecError::Unavailable);
            }
            return slot
                .adapter
                .get_or_try_init(|| async {
                    // Callers queued behind a failed open run this closure
                    // in turn; without the recheck each would pay its own
                    // connect timeout against the same dead target.
                    if slot.recently_failed().await {
                        return Err(ExecError::Unavailable);
                    }
                    let opened = open(server, database, &self.detached).await;
                    if opened.is_err() {
                        slot.record_failure().await;
                    }
                    opened
                })
                .await
                .map(Arc::clone);
        }
    }

    /// Drop every adapter for `(server, database)`. The next lookup opens a
    /// fresh one; callers already holding the old adapter finish their work
    /// on it, and its pools close when the last of them lets go. Used by
    /// config reload and stale-credential replacement.
    pub async fn evict(&self, server: &str, database: &str) {
        self.inner
            .write()
            .await
            .remove(&(server.to_string(), database.to_string()));
    }

    /// The slot for `key` opened from `fingerprint`, created if absent.
    /// Read first — the steady-state hit — and take the write lock only to
    /// create a slot or retire a sibling. Neither guard outlives this call.
    ///
    /// Each fingerprint keeps its own slot, so requests on either side of a
    /// reload never replace each other's adapter (which would open a pool per
    /// switch and split each caller's share across them). The side no request
    /// asks for any more retires after [`SNAPSHOT_LIFETIME`].
    async fn slot(&self, key: &AdapterKey, fingerprint: Fingerprint) -> Arc<Slot> {
        if let Some(slots) = self.inner.read().await.get(key)
            && let Some(slot) = slots.iter().find(|s| s.fingerprint == fingerprint)
        {
            slot.touch();
            if !slot::has_retired(slots, fingerprint, SNAPSHOT_LIFETIME) {
                return Arc::clone(slot);
            }
        }
        // Another task may have inserted a matching slot while we waited for
        // the write lock; keep it rather than adding a second.
        let mut map = self.inner.write().await;
        let slots = map.entry(key.clone()).or_default();
        slot::retire(slots, fingerprint, SNAPSHOT_LIFETIME);
        let slot = match slots.iter().find(|s| s.fingerprint == fingerprint) {
            Some(slot) => Arc::clone(slot),
            None => {
                let slot = Arc::new(Slot::new(fingerprint));
                slots.push(Arc::clone(&slot));
                slot
            }
        };
        slot.touch();
        slot
    }

    /// Remove `slot` only if it is still the one there, so two callers that
    /// both saw the stale adapter evict it once, not the fresh replacement
    /// the first of them opened.
    async fn evict_slot(&self, key: &AdapterKey, slot: &Arc<Slot>) {
        let mut map = self.inner.write().await;
        if let Some(slots) = map.get_mut(key) {
            slots.retain(|current| !Arc::ptr_eq(current, slot));
            if slots.is_empty() {
                map.remove(key);
            }
        }
    }
}

async fn open(
    server: &Server,
    database: &Database,
    detached: &DetachedTasks,
) -> Result<Arc<dyn DbAdapter>, ExecError> {
    let sizing = PoolSizing::resolve(server, database).map_err(|err| {
        tracing::warn!(
            server = %server.name,
            database = %database.name,
            min = err.min,
            max = err.max,
            "target pool sizing invalid"
        );
        ExecError::Connection
    })?;
    Ok(match server.kind {
        ServerKind::Postgres => {
            Arc::new(PgAdapter::open(server, database, sizing, detached.clone()).await?)
        }
        ServerKind::Mongo => {
            Arc::new(MongoAdapter::open(server, database, sizing, detached.clone()).await?)
        }
        ServerKind::Redis => Arc::new(RedisAdapter::open(server, database, sizing).await?),
        other => return Err(ExecError::UnsupportedAdapter(other)),
    })
}
