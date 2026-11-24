//! [`AdapterRegistry`]: one lazily-opened adapter per `(server, database)`
//! and config snapshot, replaced when it goes stale and not re-opened while
//! its target is down.

mod fingerprint;
mod slot;
mod sweep;
#[cfg(test)]
mod tests;

use std::hash::RandomState;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::audit::drain::DetachedTasks;
use crate::config::{ConfigFile, Database, Server, ServerKind};

use super::adapter::{DbAdapter, ExecError};
use super::mongo::MongoAdapter;
use super::pg::PgAdapter;
use super::pool_sizing::PoolSizing;
use super::redis::RedisAdapter;
use fingerprint::Fingerprint;
use slot::Slot;
use sweep::Slots;

/// How long a failed open is remembered. Opening a dead target costs up to
/// the pool acquire timeout; without this every request to it would pay that
/// again while holding a global request permit.
const FAILED_OPEN_TTL: Duration = Duration::from_secs(5);

/// How long a superseded slot a request still holds outlives its last
/// lookup. A request carries its config snapshot for at most
/// `transport::MCP_TIMEOUT`, so past this no straggler from before a reload
/// can still ask for it.
const SNAPSHOT_LIFETIME: Duration = Duration::from_secs(300);

/// How often superseded slots are re-checked after a reload, until none is
/// left.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// Composite key for the registry: `(server.name, database.name)`.
type AdapterKey = (String, String);

/// Per-`(server, database)` adapter registry. Hands out `Arc<dyn DbAdapter>`
/// keyed on `(server.name, database.name)` so a slow query on DB A can never
/// block DB B (each adapter owns its own pool).
///
/// Dispatch is on `server.kind`: `Postgres`, `Mongo` and `Redis` are wired; the
/// remaining `ServerKind` variants return `ExecError::UnsupportedAdapter`.
/// `ServerKind::has_adapter` is the shared source of truth — config
/// validation rejects unwired kinds at boot, so that arm is a backstop a
/// validated config never reaches.
#[derive(Clone)]
pub struct AdapterRegistry {
    inner: Arc<RwLock<Slots>>,
    /// Handed to every adapter for its detached cancels.
    detached: DetachedTasks,
    /// Keys every slot's [`Fingerprint`]; shared by clones.
    fingerprint_keys: RandomState,
    sweep_every: Duration,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            detached: DetachedTasks::default(),
            fingerprint_keys: RandomState::new(),
            sweep_every: SWEEP_EVERY,
        }
    }
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

    /// A registry that re-checks superseded slots every `sweep_every` rather
    /// than [`SWEEP_EVERY`] — for tests that watch a retired pool close.
    pub fn with_sweep_interval(sweep_every: Duration) -> Self {
        Self {
            sweep_every,
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
            .map
            .remove(&(server.to_string(), database.to_string()));
    }

    /// Make `config` the current one: every slot opened from other settings
    /// — a changed or removed database — is superseded. Those no request
    /// holds close now; the rest are re-checked every sweep interval until
    /// released or [`SNAPSHOT_LIFETIME`] passes without a lookup.
    pub async fn retire_superseded(&self, config: &ConfigFile) {
        let current = config
            .servers
            .iter()
            .flat_map(|server| {
                server.databases.iter().map(move |database| {
                    let key = (server.name.clone(), database.name.clone());
                    (
                        key,
                        Fingerprint::of(&self.fingerprint_keys, server, database),
                    )
                })
            })
            .collect();
        let mut state = self.inner.write().await;
        state.current = Some(current);
        if state.sweep(SNAPSHOT_LIFETIME) > 0 {
            self.ensure_sweeper(&mut state);
        }
    }

    /// The slot for `key` opened from `fingerprint`, created if absent.
    /// Read first — the steady-state hit — and take the write lock only to
    /// create a slot. Neither guard outlives this call.
    ///
    /// Each fingerprint keeps its own slot, so requests on either side of a
    /// reload never replace each other's adapter (which would open a pool per
    /// switch and split each caller's share across them). A slot created for
    /// a superseded snapshot (a straggler, or a removed database) starts the
    /// sweeper, so it never outlives its last holder.
    async fn slot(&self, key: &AdapterKey, fingerprint: Fingerprint) -> Arc<Slot> {
        if let Some(slot) = self.inner.read().await.find(key, fingerprint) {
            slot.touch();
            return slot;
        }
        // Another task may have inserted a matching slot while we waited for
        // the write lock; keep it rather than adding a second.
        let mut state = self.inner.write().await;
        let slot = match state.find(key, fingerprint) {
            Some(slot) => slot,
            None => {
                let slot = Arc::new(Slot::new(fingerprint));
                state
                    .map
                    .entry(key.clone())
                    .or_default()
                    .push(Arc::clone(&slot));
                if state.is_superseded(key, fingerprint) {
                    self.ensure_sweeper(&mut state);
                }
                slot
            }
        };
        slot.touch();
        slot
    }

    /// Start the sweeper unless one is running. Called and cleared under the
    /// write lock, so a superseded slot is never added after the sweeper
    /// decided to stop.
    fn ensure_sweeper(&self, state: &mut Slots) {
        if state.sweeping {
            return;
        }
        state.sweeping = true;
        let registry = self.clone();
        tokio::spawn(async move { registry.sweep_until_settled().await });
    }

    async fn sweep_until_settled(&self) {
        loop {
            tokio::time::sleep(self.sweep_every).await;
            let mut state = self.inner.write().await;
            if state.sweep(SNAPSHOT_LIFETIME) == 0 {
                state.sweeping = false;
                return;
            }
        }
    }

    /// Remove `slot` only if it is still the one there, so two callers that
    /// both saw the stale adapter evict it once, not the fresh replacement
    /// the first of them opened.
    async fn evict_slot(&self, key: &AdapterKey, slot: &Arc<Slot>) {
        let mut state = self.inner.write().await;
        let map = &mut state.map;
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
