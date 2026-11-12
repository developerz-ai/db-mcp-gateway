//! `permissions_audit` — the admin API's synchronous change log.

use crate::audit::permissions::PermissionsAuditRow;
#[cfg(any(test, debug_assertions))]
use {
    crate::audit::permissions::{
        PermissionsAuditAction, PermissionsAuditError, PermissionsAuditTargetType,
    },
    chrono::{DateTime, Utc},
    sqlx::{PgPool, Row},
};

/// Insert one `permissions_audit` row. Takes any executor so admin handlers
/// can run it inside the transaction that holds the data change.
pub async fn insert_permissions_change(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    row: &PermissionsAuditRow,
) -> Result<(), sqlx::Error> {
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
    .await?;
    Ok(())
}

/// Most recent `permissions_audit` row for `(target_type, target_id)`, with
/// its server-assigned timestamp. Test-only read.
#[cfg(any(test, debug_assertions))]
pub async fn latest_permissions_change(
    pool: &PgPool,
    target_type: PermissionsAuditTargetType,
    target_id: uuid::Uuid,
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
