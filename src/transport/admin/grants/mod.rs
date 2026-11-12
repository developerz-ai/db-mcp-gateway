//! `/admin/v1/grants` handlers (#54).
//!
//! Grants are the `(user, target, action, constraints)` mapping the authz
//! engine reads. Every write runs through
//! [`super::audited_tx::AuditedTx`], whose commit notifies every replica and
//! drops the affected user's cached grant set — a live grant change is
//! reflected on the next tool call.
//!
//! ## XOR target
//!
//! [`GrantTarget`](crate::state::permissions::GrantTarget) is exactly one of
//! `Specific { database_id }` or `Wildcard { server }`. The request DTO
//! exposes both as optional fields (spec 12's example payload) and
//! [`validation::parse_grant_target`] enforces the XOR. PATCH cannot change
//! the target — that's the grant's identity; re-target by DELETE + POST.

mod dto;
mod handlers;
mod validation;

use std::sync::Arc;

use sqlx::PgPool;

use crate::authz::PermissionsCache;
use crate::state::permissions::PermissionsRepo;

pub use dto::{CreateGrantRequest, GrantResponse, ListGrantsQuery, UpdateGrantRequest};
pub use handlers::{create, delete, get_one, list, patch};

/// Shared state cloned into every grants-route handler.
#[derive(Clone)]
pub struct GrantsState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
    pub cache: PermissionsCache,
    /// Server names the gateway config declares — the only legal wildcard
    /// targets.
    pub known_servers: Arc<[String]>,
}

impl std::fmt::Debug for GrantsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantsState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .field("cache", &self.cache)
            .field("known_servers", &self.known_servers)
            .finish()
    }
}
