//! Audit log writer.
//!
//! Spec: docs/initial-idea/07-logging-retention.md. CLAUDE.md
//! non-negotiable: every tool dispatch traces to an SSO-verified identity →
//! audit row, and audit-write failures **fail the request**. No best-effort.
//!
//! Retention pruner lives in `audit::pruner` (issue #8 Slice 3). Archive +
//! stream sinks (S3/GCS/OTLP/Kafka per spec 07) are out of scope for #8 and
//! land in follow-up issues.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// One row in `audit_calls`. Fields mirror spec 07 §Fields. Most fields are
/// `Option` because not every tool / outcome populates them (e.g.
/// `list_servers` has no `row_count`; a successful call has no
/// `error_message`).
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub request_id: String,
    pub user_sub: String,
    pub user_email: String,
    /// Group snapshot at request time (sourced from the session). Stored so
    /// later group changes don't retroactively re-explain why a request was
    /// allowed.
    pub groups: Vec<String>,
    pub tool: String,
    pub server: Option<String>,
    pub database: Option<String>,
    /// The SQL the agent submitted, if any. `list_servers` etc. leave this
    /// `None`. Spec 08's `sql_capture: full | redacted | metadata_only`
    /// policy lands in a follow-up.
    pub sql: Option<String>,
    pub reason: Option<String>,
    /// `"success"` or one of the spec 03 error codes (`forbidden`, `timeout`,
    /// `syntax_error`, `unavailable`, `reason_required`, `internal`,
    /// `forbidden_sql`).
    pub outcome: String,
    pub elapsed_ms: Option<i64>,
    pub row_count: Option<i64>,
    pub truncated: Option<bool>,
    /// User-facing error message we returned. NEVER includes raw DB error
    /// strings or connection details — tools sanitize these in
    /// `outcome_from_exec_error` paths.
    pub error_message: Option<String>,
    /// MCP client banner (self-reported via `User-Agent` until we wire the
    /// proper MCP `clientInfo` from initialize).
    pub agent_client: Option<String>,
    /// Source IP of the request socket, formatted as a string (we store
    /// TEXT not INET — see migration 0003).
    pub ip: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit write failed")]
    Write(#[source] sqlx::Error),
}

/// Persist one audit row. Synchronous on the request path: callers MUST
/// propagate this error to the agent so an unaudited call never succeeds.
pub async fn log(pool: &PgPool, row: &AuditRow) -> Result<(), AuditError> {
    let groups_json = serde_json::to_value(&row.groups).unwrap_or(serde_json::Value::Array(vec![]));
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, groups, tool, server_name, database_name, \
          sql, reason, outcome, elapsed_ms, row_count, truncated, error_message, \
          agent_client, ip) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
    )
    .bind(Uuid::new_v4())
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
    .execute(pool)
    .await
    .map_err(AuditError::Write)?;
    Ok(())
}

/// Convenience read for tests. Looks up the most recent audit row for a
/// given (user_sub, tool). Not part of the production surface.
#[cfg(any(test, debug_assertions))]
pub async fn latest_for_user_tool(
    pool: &PgPool,
    user_sub: &str,
    tool: &str,
) -> Result<Option<AuditRow>, AuditError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT request_id, user_sub, user_email, groups, tool, server_name, database_name, \
                sql, reason, outcome, elapsed_ms, row_count, truncated, error_message, \
                agent_client, ip, occurred_at \
         FROM audit_calls WHERE user_sub = $1 AND tool = $2 \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(user_sub)
    .bind(tool)
    .fetch_optional(pool)
    .await
    .map_err(AuditError::Write)?;

    Ok(row.map(|r| {
        let _occurred: DateTime<Utc> = r.get("occurred_at");
        let groups: Vec<String> = r
            .try_get::<serde_json::Value, _>("groups")
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        AuditRow {
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
        }
    }))
}
