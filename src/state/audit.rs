//! State-DB queries for the two audit tables, `audit_calls` and
//! `permissions_audit`. Only the SQL and row mapping live here; the audit
//! layer (`crate::audit`) keeps the policy around them — the write deadline,
//! the retention floor, the typed errors callers see.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::audit::permissions::PermissionsAuditRow;
// Reached only from the test-only `latest_permissions_change` read below.
#[cfg(any(test, debug_assertions))]
use crate::audit::permissions::{
    PermissionsAuditAction, PermissionsAuditError, PermissionsAuditTargetType,
};
use crate::audit::{AuditRow, HistoryEntry};

/// Insert one `audit_calls` row. `ON CONFLICT (id) DO NOTHING` makes the
/// write idempotent when the request-path guard fires a fallback insert after
/// a timed-out primary write: even in the (theoretically possible)
/// SQLx-cancellation race where the primary INSERT still commits, the
/// fallback with the same `id` becomes a no-op instead of a duplicate row.
/// Append-only semantics are preserved — never UPDATE, only skip inserting.
pub async fn insert_call(pool: &PgPool, row: &AuditRow) -> Result<(), sqlx::Error> {
    let groups_json = serde_json::to_value(&row.groups).unwrap_or(serde_json::Value::Array(vec![]));
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, groups, tool, server_name, database_name, \
          sql, reason, outcome, elapsed_ms, row_count, truncated, error_message, \
          agent_client, ip, db_type) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(row.id)
    .bind(&row.request_id)
    .bind(&row.user_sub)
    .bind(&row.user_email)
    .bind(&groups_json)
    .bind(&row.tool)
    .bind(&row.server)
    .bind(&row.database)
    .bind(&row.sql)
    .bind(&row.reason)
    .bind(&row.outcome)
    .bind(row.elapsed_ms)
    .bind(row.row_count)
    .bind(row.truncated)
    .bind(&row.error_message)
    .bind(&row.agent_client)
    .bind(&row.ip)
    .bind(&row.db_type)
    .execute(pool)
    .await?;
    Ok(())
}

/// Most recent `audit_calls` row for `(user_sub, tool)`. Test-only read.
#[cfg(any(test, debug_assertions))]
pub async fn latest_call_for_user_tool(
    pool: &PgPool,
    user_sub: &str,
    tool: &str,
) -> Result<Option<AuditRow>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, request_id, user_sub, user_email, groups, tool, server_name, database_name, \
                sql, reason, outcome, elapsed_ms, row_count, truncated, error_message, \
                agent_client, ip, db_type, occurred_at \
         FROM audit_calls WHERE user_sub = $1 AND tool = $2 \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(user_sub)
    .bind(tool)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| {
        let groups: Vec<String> = r
            .try_get::<serde_json::Value, _>("groups")
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        AuditRow {
            id: r.get("id"),
            request_id: r.get("request_id"),
            user_sub: r.get("user_sub"),
            user_email: r.get("user_email"),
            groups,
            tool: r.get("tool"),
            server: r.get("server_name"),
            database: r.get("database_name"),
            sql: r.get("sql"),
            reason: r.get("reason"),
            outcome: r.get("outcome"),
            elapsed_ms: r.get("elapsed_ms"),
            row_count: r.get("row_count"),
            truncated: r.get("truncated"),
            error_message: r.get("error_message"),
            agent_client: r.get("agent_client"),
            ip: r.get("ip"),
            db_type: r.get("db_type"),
        }
    }))
}

/// SECURITY-CRITICAL — used by `tools::get_query_history`. One caller's
/// `audit_calls` rows for `(server, database)`, newest first, scoped by the
/// SSO-verified `user_sub` (never a client-supplied field). `limit` arrives
/// pre-clamped to `GATEWAY_ROW_LIMIT_CEILING`. The composite index `(user_sub, occurred_at DESC)` from migration 0003
/// covers the WHERE + ORDER BY exactly.
pub async fn select_user_history(
    pool: &PgPool,
    user_sub: &str,
    server: &str,
    database: &str,
    since: Option<DateTime<Utc>>,
    limit: u32,
) -> Result<Vec<HistoryEntry>, sqlx::Error> {
    // `$4::timestamptz` so the bind type is unambiguous when `since` is
    // NULL — sqlx otherwise can't tell `TIMESTAMPTZ` from `TEXT`.
    let rows = sqlx::query(
        "SELECT request_id, sql, reason, outcome, elapsed_ms, row_count, occurred_at \
         FROM audit_calls \
         WHERE user_sub = $1 AND server_name = $2 AND database_name = $3 \
           AND ($4::timestamptz IS NULL OR occurred_at >= $4::timestamptz) \
         ORDER BY occurred_at DESC \
         LIMIT $5",
    )
    .bind(user_sub)
    .bind(server)
    .bind(database)
    .bind(since)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let occurred: DateTime<Utc> = r.try_get("occurred_at").unwrap_or_else(|_| Utc::now());
            HistoryEntry {
                request_id: r.get("request_id"),
                sql: r.try_get("sql").ok(),
                reason: r.try_get("reason").ok(),
                outcome: r.get("outcome"),
                elapsed_ms: r.try_get("elapsed_ms").ok(),
                row_count: r.try_get("row_count").ok(),
                occurred_at: occurred.to_rfc3339(),
            }
        })
        .collect())
}

/// Delete every `audit_calls` row older than `days`. Returns rows removed.
pub async fn delete_calls_older_than(pool: &PgPool, days: i32) -> Result<u64, sqlx::Error> {
    // `interval '1 day' * $1` keeps the SQL portable to older Postgres
    // versions (`make_interval` is 14+). The cast on the bind is needed so
    // sqlx infers the parameter type — Postgres won't let `int * interval`
    // happen with a freshly-bound untyped param.
    let result = sqlx::query(
        "DELETE FROM audit_calls \
         WHERE occurred_at < now() - (interval '1 day' * $1::int)",
    )
    .bind(days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

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
