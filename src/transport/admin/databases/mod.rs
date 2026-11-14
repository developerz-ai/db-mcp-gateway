//! `/admin/v1/databases` handlers (#53).
//!
//! Register/manage the logical `(server, db_name, db_type)` records specific
//! grants attach to. Every write runs through
//! [`super::audited_tx::AuditedTx`] (CLAUDE.md MUST #4).
//!
//! ## DSN never crosses this surface
//!
//! Per spec 12 §"What the API never returns" and CLAUDE.md MUST #1:
//!
//! - **Out:** `permissions_databases` has no credential columns, so the
//!   response struct cannot leak one.
//! - **In:** request DTOs declare `#[serde(deny_unknown_fields)]`. A body
//!   carrying `connection_string`, `dsn`, `password`, `role`, or any other
//!   unknown field is rejected at parse time with `400 invalid_request` — the
//!   handler never sees it, so it cannot log or echo it.
//!
//! ## Cache impact
//!
//! A wildcard grant resolves against the *config's* databases, never these
//! rows, and a new row has no grants yet — so a create changes no cached
//! grant set. A rename or soft-delete changes what every specific grant on
//! the row resolves to, so those flush the whole cache.

mod dto;
mod handlers;
mod validation;

use std::sync::Arc;

use sqlx::PgPool;

use crate::authz::PermissionsCache;
use crate::state::permissions::PermissionsRepo;

pub use dto::{CreateDatabaseRequest, DatabaseResponse, UpdateDatabaseRequest};
pub use handlers::{create, delete, get_one, list, patch};

/// Shared state cloned into every databases-route handler.
#[derive(Clone)]
pub struct DatabasesState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
    pub cache: PermissionsCache,
    /// Server names the gateway config declares — the only servers a
    /// database may be registered on.
    pub known_servers: Arc<[String]>,
}

impl std::fmt::Debug for DatabasesState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabasesState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .field("cache", &self.cache)
            .field("known_servers", &self.known_servers)
            .finish()
    }
}
