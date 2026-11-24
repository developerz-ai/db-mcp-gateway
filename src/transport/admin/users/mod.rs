//! `/admin/v1/users` handlers (#52).
//!
//! Every write runs through [`super::audited_tx::AuditedTx`]: data change and
//! `permissions_audit` row commit together or not at all (CLAUDE.md MUST #4).

mod handlers;
mod revoke;

pub use handlers::{create, delete, get_one, list, patch};
pub use revoke::revoke_sessions;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::SessionStore;
use crate::auth::session::is_service_subject;
use crate::authz::PermissionsCache;
use crate::state::permissions::{PermissionsRepo, PermissionsUser};

use super::error::AdminError;
use super::validation::trimmed_non_empty;

/// OIDC Core §2: `sub` "MUST NOT exceed 255 ASCII characters".
const MAX_SUB_LEN: usize = 255;
/// RFC 5321 path limit; no deliverable address is longer.
const MAX_EMAIL_LEN: usize = 254;
const MAX_GROUP_LEN: usize = 255;
/// Far above any real membership list, low enough to bound a row's JSONB.
const MAX_GROUPS: usize = 256;

/// Shared state cloned into every users-route handler.
#[derive(Clone)]
pub struct UsersState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
    pub cache: PermissionsCache,
    pub sessions: SessionStore,
}

impl std::fmt::Debug for UsersState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsersState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .field("cache", &self.cache)
            .field("sessions", &"<SessionStore>")
            .finish()
    }
}

/// Public response shape. A dedicated DTO so adding fields to the storage
/// struct doesn't accidentally widen the admin surface.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// Optimistic-concurrency precondition: 409 if the row's `updated_at`
    /// differs.
    #[serde(default)]
    pub expected_updated_at: Option<DateTime<Utc>>,
}

/// Validate a `user_sub`: non-empty, bounded, and not a YAML service identity
/// (`service:<name>`, spec 14 — its authority is exactly its YAML group, so
/// the admin API never creates a DB-grant-bearing row for one). The prefix
/// check is case-insensitive, matching the login-time refusal.
fn sso_subject(value: &str, request_id: &str) -> Result<String, AdminError> {
    let sub = bounded(value, "user_sub", MAX_SUB_LEN, request_id)?;
    if is_service_subject(&sub) {
        return Err(AdminError::invalid(
            "user_sub `service:*` is a YAML service identity; its grants are its YAML group only",
        )
        .with_request_id(request_id));
    }
    Ok(sub)
}

fn valid_email(value: &str, request_id: &str) -> Result<String, AdminError> {
    bounded(value, "user_email", MAX_EMAIL_LEN, request_id)
}

/// Normalize each group name like the other string fields, so blank entries
/// never reach `permissions_users.groups`.
fn validate_groups(groups: &[String], request_id: &str) -> Result<Vec<String>, AdminError> {
    if groups.len() > MAX_GROUPS {
        return Err(
            AdminError::invalid(format!("groups must list at most {MAX_GROUPS} entries"))
                .with_request_id(request_id),
        );
    }
    groups
        .iter()
        .map(|g| bounded(g, "groups[]", MAX_GROUP_LEN, request_id))
        .collect()
}

/// [`trimmed_non_empty`], at most `max` bytes once trimmed.
fn bounded(value: &str, field: &str, max: usize, request_id: &str) -> Result<String, AdminError> {
    let trimmed = trimmed_non_empty(value, field, request_id)?;
    if trimmed.len() > max {
        return Err(
            AdminError::invalid(format!("{field} must be at most {max} bytes"))
                .with_request_id(request_id),
        );
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn sso_subject_rejects_service_prefix() {
        assert!(sso_subject("service:ci-bot", "r").is_err());
        assert!(sso_subject("  service:ci-bot", "r").is_err());
        assert!(sso_subject("SERVICE:ci-bot", "r").is_err());
        assert!(sso_subject("Service:ci-bot", "r").is_err());
        assert_eq!(sso_subject(" alice ", "r").unwrap(), "alice");
        // Only the prefix is reserved, not the word.
        assert!(sso_subject("my-service:x", "r").is_ok());
    }

    #[test]
    fn subject_email_and_groups_are_length_bounded() {
        assert!(sso_subject(&"s".repeat(MAX_SUB_LEN), "r").is_ok());
        assert!(sso_subject(&"s".repeat(MAX_SUB_LEN + 1), "r").is_err());
        assert!(valid_email(&"e".repeat(MAX_EMAIL_LEN), "r").is_ok());
        assert!(valid_email(&"e".repeat(MAX_EMAIL_LEN + 1), "r").is_err());
        assert!(validate_groups(&["g".repeat(MAX_GROUP_LEN)], "r").is_ok());
        assert!(validate_groups(&["g".repeat(MAX_GROUP_LEN + 1)], "r").is_err());
        assert!(validate_groups(&vec!["g".to_string(); MAX_GROUPS], "r").is_ok());
        assert!(validate_groups(&vec!["g".to_string(); MAX_GROUPS + 1], "r").is_err());
    }
}
