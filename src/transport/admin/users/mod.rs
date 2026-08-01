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

use crate::authz::PermissionsCache;
use crate::state::permissions::{PermissionsRepo, PermissionsUser};

use super::error::AdminError;

/// Shared state cloned into every users-route handler. The `cache` field is
/// `Option<PermissionsCache>` because YAML-only installs (no state DB pool)
/// run without a resolver cache — invalidation is then a no-op. Mirrors the
/// wiring in [`super::grants::GrantsState`] so a user mutation (patch/delete)
/// drops the cached grant set that referenced them; without it, a revoked or
/// re-grouped user keeps getting the old authz decision for up to the cache
/// TTL.
#[derive(Clone)]
pub struct UsersState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
    pub cache: Option<PermissionsCache>,
}

impl std::fmt::Debug for UsersState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsersState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .field("cache", &self.cache.as_ref().map(|_| "<PermissionsCache>"))
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

/// Validate + normalize each group name like the other string fields, so
/// empty/whitespace-only entries can't reach `permissions_users.groups` —
/// authz constraint-merge reads these later for grant evaluation.
pub(super) fn validate_groups(
    groups: &[String],
    request_id: &str,
) -> Result<Vec<String>, AdminError> {
    groups
        .iter()
        .map(|g| trimmed_non_empty(g, "groups[]", request_id))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn trimmed_non_empty_rejects_blank() {
        assert!(trimmed_non_empty("", "user_sub", "req-1").is_err());
        assert!(trimmed_non_empty("   ", "user_sub", "req-1").is_err());
        assert!(trimmed_non_empty("\t\n", "user_sub", "req-1").is_err());
    }

    #[test]
    fn trimmed_non_empty_trims_and_returns() {
        assert_eq!(
            trimmed_non_empty("  alice  ", "user_sub", "req-1").unwrap(),
            "alice"
        );
    }

    #[test]
    fn validate_groups_rejects_blank_member() {
        assert!(validate_groups(&["ok".into(), "  ".into()], "req-1").is_err());
    }

    #[test]
    fn validate_groups_trims_each_member() {
        let out = validate_groups(&[" eng ".into(), "ops".into()], "req-1").unwrap();
        assert_eq!(out, vec!["eng".to_string(), "ops".to_string()]);
    }

    #[test]
    fn user_payload_serializes_expected_shape() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let user = PermissionsUser {
            id: Uuid::nil(),
            user_sub: "sub-123".into(),
            user_email: "a@example.com".into(),
            groups: vec!["engineers".into()],
            created_at: ts,
            updated_at: ts,
            deleted_at: None,
        };
        let payload = user_payload(&user);
        assert_eq!(payload["id"], json!(Uuid::nil()));
        assert_eq!(payload["user_sub"], "sub-123");
        assert_eq!(payload["user_email"], "a@example.com");
        assert_eq!(payload["groups"], json!(["engineers"]));
        assert_eq!(payload["created_at"], json!(ts));
        assert_eq!(payload["updated_at"], json!(ts));
        // Storage-only field must not widen the admin payload.
        assert!(payload.get("deleted_at").is_none());
    }
}
