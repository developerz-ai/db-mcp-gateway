//! `/admin/v1/users` handlers (#52).
//!
//! Every write opens a state-DB transaction, calls the repo, writes the
//! `permissions_audit` row through the same transaction, then commits. Audit
//! failure → transaction rolls back → handler returns 5xx. CLAUDE.md
//! non-negotiable #4 (synchronous audit) honored end-to-end.

mod handlers;
mod tx;

pub use handlers::{create, delete, get_one, list, patch};

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::state::permissions::{PermissionsRepo, PermissionsUser};

use super::error::AdminError;

/// Shared state cloned into every users-route handler.
#[derive(Clone)]
pub struct UsersState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
}

impl std::fmt::Debug for UsersState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsersState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .finish()
    }
}

/// Public response shape. Carries no credentials — `permissions_users` rows
/// never hold any — but kept as a dedicated DTO so adding fields to the
/// storage struct doesn't accidentally widen the admin surface.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PermissionsUser> for UserResponse {
    fn from(u: PermissionsUser) -> Self {
        Self {
            id: u.id,
            user_sub: u.user_sub,
            user_email: u.user_email,
            groups: u.groups,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub user_sub: String,
    pub user_email: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
}

/// Map a `JsonRejection` (malformed/missing body, bad content-type) onto the
/// stable admin-error envelope so clients see `invalid_request` + `request_id`
/// instead of Axum's default 400/422.
pub(super) fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

/// Map a `PathRejection` (malformed UUID in `:id`) onto the stable admin-error
/// envelope.
pub(super) fn invalid_id(request_id: &str) -> AdminError {
    AdminError::invalid("invalid user id").with_request_id(request_id)
}

pub(super) fn trimmed_non_empty(
    value: &str,
    field: &str,
    request_id: &str,
) -> Result<String, AdminError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(AdminError::invalid(format!("{field} must be non-empty")).with_request_id(request_id))
    } else {
        Ok(trimmed.to_string())
    }
}

pub(super) fn user_payload(u: &PermissionsUser) -> JsonValue {
    json!({
        "id": u.id,
        "user_sub": u.user_sub,
        "user_email": u.user_email,
        "groups": u.groups,
        "created_at": u.created_at,
        "updated_at": u.updated_at,
    })
}

/// Build an `internal` admin error and trace the failure.
///
/// We log only `stage`, `error_type`, and `request_id` — never `%err`. A
/// PostgreSQL error's `Display` impl embeds `detail`/`constraint` text, which
/// on `permissions_users` carries user emails and group names. CLAUDE.md
/// non-negotiable #1 forbids leaking that into logs.
pub(super) fn internal<E>(stage: &'static str, _err: E, request_id: &str) -> AdminError {
    let error_type = std::any::type_name::<E>();
    tracing::error!(
        stage,
        error_type,
        %request_id,
        "admin users endpoint failed"
    );
    AdminError::internal().with_request_id(request_id)
}
