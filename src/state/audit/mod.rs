//! State-DB queries for the audit tables: `audit_calls`, `audit_call_intents`
//! and `permissions_audit`. Only the SQL and row mapping live here; the audit
//! layer (`crate::audit`) keeps the policy around them — the write deadline,
//! the retention floor, the reaper grace, the typed errors callers see.

mod history;
mod intents;
mod permissions;
mod retention;

pub use history::select_user_history;
pub use intents::{
    IntentKey, ReapBatch, insert_intent, reap_abandoned_batch, select_intent_access,
    select_owned_request_ids,
};
pub use permissions::insert_permissions_change;
#[cfg(any(test, debug_assertions))]
pub use permissions::latest_permissions_change;
pub use retention::{
    RetentionTable, delete_expired_batch, referenced_expired_parents, retention_cutoff,
};

use sqlx::PgPool;
#[cfg(any(test, debug_assertions))]
use sqlx::Row;

use crate::audit::AuditRow;
#[cfg(any(test, debug_assertions))]
use crate::audit::OutcomeCode;

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
          agent_client, ip, db_type, upstream_actor, upstream_run_id, rows_affected, \
          sql_truncated) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
                 $19, $20, $21, $22) \
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
    .bind(row.outcome.as_str())
    .bind(row.elapsed_ms)
    .bind(row.row_count)
    .bind(row.truncated)
    .bind(&row.error_message)
    .bind(&row.agent_client)
    .bind(&row.ip)
    .bind(&row.db_type)
    .bind(&row.upstream_actor)
    .bind(&row.upstream_run_id)
    .bind(row.rows_affected)
    .bind(row.sql_truncated)
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
                agent_client, ip, db_type, upstream_actor, upstream_run_id, rows_affected, \
                sql_truncated, occurred_at \
         FROM audit_calls WHERE user_sub = $1 AND tool = $2 \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(user_sub)
    .bind(tool)
    .fetch_optional(pool)
    .await?;
    let Some(r) = row else { return Ok(None) };

    let groups: Option<serde_json::Value> = r.try_get("groups")?;
    let groups = match groups {
        Some(value) => {
            serde_json::from_value(value).map_err(|err| sqlx::Error::Decode(Box::new(err)))?
        }
        None => Vec::new(),
    };
    let outcome: String = r.try_get("outcome")?;
    let outcome = OutcomeCode::parse(&outcome)
        .ok_or_else(|| sqlx::Error::Decode(format!("unknown audit outcome `{outcome}`").into()))?;
    Ok(Some(AuditRow {
        id: r.try_get("id")?,
        request_id: r.try_get("request_id")?,
        user_sub: r.try_get("user_sub")?,
        user_email: r.try_get("user_email")?,
        groups,
        tool: r.try_get("tool")?,
        server: r.try_get("server_name")?,
        database: r.try_get("database_name")?,
        sql: r.try_get("sql")?,
        reason: r.try_get("reason")?,
        outcome,
        elapsed_ms: r.try_get("elapsed_ms")?,
        row_count: r.try_get("row_count")?,
        truncated: r.try_get("truncated")?,
        error_message: r.try_get("error_message")?,
        agent_client: r.try_get("agent_client")?,
        ip: r.try_get("ip")?,
        db_type: r.try_get("db_type")?,
        upstream_actor: r.try_get("upstream_actor")?,
        upstream_run_id: r.try_get("upstream_run_id")?,
        rows_affected: r.try_get("rows_affected")?,
        sql_truncated: r.try_get("sql_truncated")?,
    }))
}
