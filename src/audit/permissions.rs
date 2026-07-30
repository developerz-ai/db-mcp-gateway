//! Synchronous writer for the admin-API audit trail (#51).
//!
//! Spec: docs/initial-idea/12-dynamic-permissions.md §"permissions_audit
//! table". Same invariant as [`super::log`] for query audit (CLAUDE.md
//! non-negotiable #4): write fails → request fails. Admin endpoints
//! (#52..#54) MUST propagate the typed `Err` and roll back their data
//! change — the writer cannot do that on its own; it doesn't know what
//! preceded it.
//!
//! Secrets: the audited tables (`permissions_users`, `permissions_databases`,
//! `permissions_grants`) don't store credentials. DSNs and role passwords
//! stay in YAML/secrets, never on a permissions row. Callers therefore
//! can't accidentally include a secret in `before`/`after` — but the
//! writer's contract still says "no secrets in JSON," so a future schema
//! change has a clear bar.

// Only `latest_for_target` below needs these, and it is cfg'd out of release
// builds — so the imports must carry the same cfg or a release build warns.
#[cfg(any(test, debug_assertions))]
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
// Same story: both are reached only from the cfg'd read helper.
#[cfg(any(test, debug_assertions))]
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// What kind of change the row records. Mirrors the
/// `permissions_audit.action` CHECK in migration `0005_permissions_audit.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionsAuditAction {
    Create,
    Update,
    Delete,
}

impl PermissionsAuditAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    pub fn parse(s: &str) -> Result<Self, PermissionsAuditError> {
        match s {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            other => Err(PermissionsAuditError::UnknownAction(other.to_string())),
        }
    }
}

/// Which permissions-store table the change touched. Mirrors the
/// `permissions_audit.target_type` CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionsAuditTargetType {
    User,
    Database,
    Grant,
}

impl PermissionsAuditTargetType {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Database => "database",
            Self::Grant => "grant",
        }
    }

    pub fn parse(s: &str) -> Result<Self, PermissionsAuditError> {
        match s {
            "user" => Ok(Self::User),
            "database" => Ok(Self::Database),
            "grant" => Ok(Self::Grant),
            other => Err(PermissionsAuditError::UnknownTargetType(other.to_string())),
        }
    }
}

/// One row in `permissions_audit`. `id` and `ts` are server-assigned and
/// therefore not part of the write contract — callers provide what they know,
/// the DB provides the rest.
#[derive(Debug, Clone)]
pub struct PermissionsAuditRow {
    /// The SSO identity making the change. UUID is the `permissions_users.id`
    /// for an in-band admin; admin bootstrap (open question in spec 12) will
    /// land with its own actor convention.
    pub actor_id: Uuid,
    /// Denormalized so forensics can read the row without joining — mirrors
    /// `audit_calls.user_email` (issue #8). Live source of truth stays the JWT.
    pub actor_email: String,
    pub action: PermissionsAuditAction,
    pub target_type: PermissionsAuditTargetType,
    /// The row id of the touched entity (a `permissions_users.id` / etc).
    pub target_id: Uuid,
    /// Full row state before the change, serialized by the caller. `None` on
    /// a `create` (there was no prior state).
    pub before: Option<JsonValue>,
    /// Full row state after the change. `None` on a `delete`.
    pub after: Option<JsonValue>,
    /// Threads the per-request id from spec 07 so an audit row can be joined
    /// back to its origin tool span in operator dashboards.
    pub request_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionsAuditError {
    #[error("permissions audit write failed")]
    Write(#[source] sqlx::Error),
    #[error("row encodes unknown action {0:?}")]
    UnknownAction(String),
    #[error("row encodes unknown target_type {0:?}")]
    UnknownTargetType(String),
}

/// Persist one permissions-audit row. Synchronous on the request path —
/// admin endpoints MUST propagate this error AND roll back the data change
/// that triggered the audit. An unaudited admin write is a CLAUDE.md
/// non-negotiable violation.
///
/// Accepts any `sqlx::Executor` (pool or transaction), enabling atomic
/// execution with rollback capability when called within admin transactions.
pub async fn log(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    row: &PermissionsAuditRow,
) -> Result<(), PermissionsAuditError> {
    sqlx::query(
        "INSERT INTO permissions_audit \
         (actor_id, actor_email, action, target_type, target_id, before, after, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(row.actor_id)
    .bind(&row.actor_email)
    .bind(row.action.as_db_str())
    .bind(row.target_type.as_db_str())
    .bind(row.target_id)
    .bind(&row.before)
    .bind(&row.after)
    .bind(&row.request_id)
    .execute(executor)
    .await
    .map_err(PermissionsAuditError::Write)?;
    Ok(())
}

/// Convenience read for tests + future admin "view audit trail" endpoints.
/// Returns the most recent row for a given `(target_type, target_id)`.
#[cfg(any(test, debug_assertions))]
pub async fn latest_for_target(
    pool: &PgPool,
    target_type: PermissionsAuditTargetType,
    target_id: Uuid,
) -> Result<Option<(PermissionsAuditRow, DateTime<Utc>)>, PermissionsAuditError> {
    let row = sqlx::query(
        "SELECT actor_id, actor_email, action, target_type, target_id, \
                before, after, request_id, ts \
         FROM permissions_audit \
         WHERE target_type = $1 AND target_id = $2 \
         ORDER BY ts DESC, id DESC \
         LIMIT 1",
    )
    .bind(target_type.as_db_str())
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .map_err(PermissionsAuditError::Write)?;

    let Some(row) = row else { return Ok(None) };
    let action_str: String = row
        .try_get("action")
        .map_err(PermissionsAuditError::Write)?;
    let target_type_str: String = row
        .try_get("target_type")
        .map_err(PermissionsAuditError::Write)?;
    let parsed = PermissionsAuditRow {
        actor_id: row
            .try_get("actor_id")
            .map_err(PermissionsAuditError::Write)?,
        actor_email: row
            .try_get("actor_email")
            .map_err(PermissionsAuditError::Write)?,
        action: PermissionsAuditAction::parse(&action_str)?,
        target_type: PermissionsAuditTargetType::parse(&target_type_str)?,
        target_id: row
            .try_get("target_id")
            .map_err(PermissionsAuditError::Write)?,
        before: row
            .try_get("before")
            .map_err(PermissionsAuditError::Write)?,
        after: row.try_get("after").map_err(PermissionsAuditError::Write)?,
        request_id: row
            .try_get("request_id")
            .map_err(PermissionsAuditError::Write)?,
    };
    let ts: DateTime<Utc> = row.try_get("ts").map_err(PermissionsAuditError::Write)?;
    Ok(Some((parsed, ts)))
}
