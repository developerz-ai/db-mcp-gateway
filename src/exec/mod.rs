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
//! and enforced on the per-adapter side; see [`pg`] for the Pg pattern.

pub mod adapter;
pub mod pg;
pub mod sql_guard;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::{Database, Server, ServerKind};

pub use adapter::{AdapterKind, DbAdapter, ExecError, ExecQuery, ExecResult};
pub use pg::PgAdapter;

/// Composite key for the registry: `(server.name, database.name)`.
type AdapterKey = (String, String);
/// Concrete map type behind the `RwLock`. Extracted to satisfy clippy's
/// type-complexity lint and to give the `Debug` impl a name to reach for.
type AdapterMap = HashMap<AdapterKey, Arc<dyn DbAdapter>>;

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
                &"<RwLock<HashMap<(server, db), Arc<dyn DbAdapter>>>>",
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
    pub async fn get_or_open(
        &self,
        server: &Server,
        database: &Database,
    ) -> Result<Arc<dyn DbAdapter>, ExecError> {
        let key = (server.name.clone(), database.name.clone());

        if let Some(adapter) = self.inner.read().await.get(&key).cloned() {
            return Ok(adapter);
        }

        // Re-check under the write lock — another task may have opened it
        // while we were waiting on the upgrade.
        let mut writer = self.inner.write().await;
        if let Some(adapter) = writer.get(&key).cloned() {
            return Ok(adapter);
        }

        let adapter: Arc<dyn DbAdapter> = match server.kind {
            ServerKind::Postgres => Arc::new(PgAdapter::open(server, database).await?),
            other => return Err(ExecError::UnsupportedAdapter(other)),
        };
        writer.insert(key, adapter.clone());
        Ok(adapter)
    }
}
