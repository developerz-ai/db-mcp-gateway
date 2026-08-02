//! Execution layer: per-`(server, database)` adapters that enforce
//! `statement_timeout`, row caps, and cancellation.
//!
//! The trait surface lives in [`adapter`]; the Postgres impl in [`pg`].
//! Tools consume an `Arc<dyn DbAdapter>` from [`AdapterRegistry`] and never
//! see backend-specific types — that's the whole point of #56's refactor:
//! mongo (#57) and mysql (#59) slot in here without touching `src/tools/`.
//!
//! Security-required (see CLAUDE.md). The non-negotiables — no credentials
//! in errors/logs, DB-side `statement_timeout` set per-tx — are documented
//! and enforced on the per-adapter side; see [`pg`] for the Pg pattern. The
//! one piece that is *not* per-adapter is the timeout ceiling
//! ([`DEFAULT_STATEMENT_TIMEOUT_MS`]): it's gateway policy, lives in
//! [`adapter`], and every impl applies it identically.

pub mod adapter;
pub mod mongo;
pub mod pg;
pub mod sql_guard;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{OnceCell, RwLock};

use crate::config::{Database, Server, ServerKind};

pub use adapter::{
    AdapterKind, DEFAULT_STATEMENT_TIMEOUT_MS, DbAdapter, ExecError, ExecQuery, ExecResult,
};
pub use mongo::MongoAdapter;
pub use pg::{DEFAULT_POOL_MAX_CONNECTIONS, PgAdapter};

/// Composite key for the registry: `(server.name, database.name)`.
type AdapterKey = (String, String);
/// One lazily-opened adapter slot.
///
/// The map stores a `OnceCell` rather than a ready adapter so the connect
/// happens *outside* the map lock: callers take the lock only long enough to
/// hand out the slot, then race to initialize it. `OnceCell` gives
/// single-flight semantics for free — concurrent callers for the same key
/// share one open attempt instead of stampeding the DB — and a failed attempt
/// leaves the cell empty, so the next caller retries (matching the lazy
/// "misconfigured DB errors on use, not at boot" contract).
type AdapterSlot = Arc<OnceCell<Arc<dyn DbAdapter>>>;
/// Concrete map type behind the `RwLock`. Extracted to satisfy clippy's
/// type-complexity lint and to give the `Debug` impl a name to reach for.
type AdapterMap = HashMap<AdapterKey, AdapterSlot>;

/// Per-`(server, database)` adapter registry. Hands out `Arc<dyn DbAdapter>`
/// keyed on `(server.name, database.name)` so a slow query on DB A can never
/// block DB B (each adapter owns its own pool).
///
/// Dispatch is on `server.kind`: today only `Postgres` is wired; other
/// `ServerKind` variants return `ExecError::UnsupportedAdapter` until their
/// adapters land (#57 mongo, #59 mysql).
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    inner: Arc<RwLock<AdapterMap>>,
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Adapter `Debug` impls already redact connection strings, but go
        // through one extra layer of `dyn` indirection just in case a future
        // impl regresses — print structural info only.
        f.debug_struct("AdapterRegistry")
            .field(
                "adapters",
                &"<RwLock<HashMap<(server, db), OnceCell<Arc<dyn DbAdapter>>>>>",
            )
            .finish()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the adapter for `(server.name, database.name)`, opening it if
    /// needed. Lazy: a misconfigured DB only errors on first use, not at
    /// boot.
    ///
    /// No lock guard is alive across the open, so a database that hangs its
    /// connect delays only callers of that same key. Concurrent callers for
    /// one key share a single open attempt.
    pub async fn get_or_open(
        &self,
        server: &Server,
        database: &Database,
    ) -> Result<Arc<dyn DbAdapter>, ExecError> {
        let key = (server.name.clone(), database.name.clone());

        // Read first — the steady-state hit — and take the write lock only to
        // create a slot that genuinely doesn't exist yet. Both guards are
        // named locals in scopes that end before the `.await` below, so
        // neither is held across it.
        let existing = self.inner.read().await.get(&key).cloned();
        let slot = match existing {
            Some(slot) => slot,
            None => {
                let mut writer = self.inner.write().await;
                // Another task may have inserted the slot while we waited for
                // the write lock; `or_default` keeps whichever landed first so
                // both callers converge on one `OnceCell`.
                writer.entry(key).or_default().clone()
            }
        };

        // Lock released. `PgAdapter::open` establishes both pools eagerly and
        // each is bounded only by the pool acquire timeout, so a down DB used
        // to park the registry's *write* lock for seconds — and because
        // tokio's `RwLock` is write-preferring, every later reader queued
        // behind it, stalling even already-open healthy databases (#136).
        slot.get_or_try_init(|| async {
            let adapter: Arc<dyn DbAdapter> = match server.kind {
                ServerKind::Postgres => Arc::new(PgAdapter::open(server, database).await?),
                ServerKind::Mongo => Arc::new(MongoAdapter::open(server, database).await?),
                other => return Err(ExecError::UnsupportedAdapter(other)),
            };
            Ok(adapter)
        })
        .await
        .map(Arc::clone)
    }
}
