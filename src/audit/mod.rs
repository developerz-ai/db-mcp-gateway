//! Audit log writer.
//!
//! Spec: docs/initial-idea/07-logging-retention.md. CLAUDE.md
//! non-negotiable: every target-DB call traces to an SSO-verified identity →
//! audit row, and audit write failures **fail the request**. No best-effort.
//!
//! Retention, archive, and external sinks land with issue #8. For #4 this
//! is the synchronous writer hook into `tools::run_query`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// One row in `audit_calls`. Fields mirror the spec; everything optional is
/// nullable in the migration too.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub request_id: String,
    pub user_sub: String,
    pub user_email: String,
    pub tool: String,
    pub server: Option<String>,
    pub database: Option<String>,
    /// The SQL the agent submitted, if any. `list_servers` etc. leave this
    /// `None`. Spec 08 will eventually let operators set `sql_capture:
    /// metadata_only | redacted | full` per database; for #4 we store the
    /// raw text and tighten in #8 when sinks land.
    pub sql: Option<String>,
    /// `"success"` or one of the spec 03 error codes (`forbidden`, `timeout`,
    /// `syntax_error`, `unavailable`, `reason_required`, `internal`).
    pub outcome: String,
    pub elapsed_ms: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit write failed")]
    Write(#[source] sqlx::Error),
}

/// Persist one audit row. Synchronous on the request path: callers MUST
/// propagate this error to the agent so an unaudited call never succeeds.
pub async fn log(pool: &PgPool, row: &AuditRow) -> Result<(), AuditError> {
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, tool, server_name, database_name, sql, outcome, elapsed_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(Uuid::new_v4())
    .bind(&row.request_id)
    .bind(&row.user_sub)
    .bind(&row.user_email)
    .bind(&row.tool)
    .bind(&row.server)
    .bind(&row.database)
    .bind(&row.sql)
    .bind(&row.outcome)
    .bind(row.elapsed_ms)
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
        "SELECT request_id, user_sub, user_email, tool, server_name, database_name, sql, outcome, elapsed_ms, occurred_at \
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
        AuditRow {
            request_id: r.get("request_id"),
            user_sub: r.get("user_sub"),
            user_email: r.get("user_email"),
            tool: r.get("tool"),
            server: r.get("server_name"),
            database: r.get("database_name"),
            sql: r.get("sql"),
            outcome: r.get("outcome"),
            elapsed_ms: r.get("elapsed_ms"),
        }
    }))
}
