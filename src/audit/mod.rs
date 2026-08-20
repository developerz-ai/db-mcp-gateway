//! Audit log writer.
//!
//! Spec: website/docs/initial-idea/07-logging-retention.md. CLAUDE.md
//! non-negotiable: every tool dispatch traces to an SSO-verified identity →
//! audit row, and audit-write failures **fail the request**. No best-effort.
//!
//! Retention pruner lives in `audit::pruner`. Stream sinks live in
//! `audit::stream` — only `stdout` ships so far (#218); syslog/OTLP and the
//! archive tier (S3/GCS/Azure) remain out of scope, tracked in #218.

pub mod permissions;
pub mod pruner;
pub mod stream;

// `latest_for_user_tool` is cfg'd out of release builds, but its chrono
// types are also used by the production `query_user_history` reader added
// with #169. One import covers both.
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

/// Hard ceiling on a single audit write. A wedged state DB must surface as a
/// typed error so the caller can fail the request — non-negotiable #4 rules
/// out an audit that hangs forever on a stuck backend. 15s is a comfortable
/// upper bound for a single-row insert; healthy writes land in single-digit
/// milliseconds. Not configurable on purpose: an operator who tunes this
/// down to 100ms would trade non-negotiable-#4 compliance for latency, and
/// tuning it up past this ceiling gives a truly wedged DB a longer window
/// to stall every in-flight request.
pub const AUDIT_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// One row in `audit_calls`. Fields mirror spec 07 §Fields. Most fields are
/// `Option` because not every tool / outcome populates them (e.g.
/// `list_servers` has no `row_count`; a successful call has no
/// `error_message`).
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// Row primary key. Callers on the request path (see
    /// `tools::audit_dispatch`) generate this once per dispatch and share
    /// it between the primary write and the drop-guard fallback so the two
    /// writes are idempotent under `ON CONFLICT (id) DO NOTHING` — a
    /// timed-out primary that ends up committing anyway will not produce a
    /// duplicate row when the fallback re-inserts.
    pub id: Uuid,
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
    /// Target backend kind — `"postgres"` or `"mongo"`. `None` for tools
    /// that don't hit a target DB (`list_servers`). Added in migration
    /// 0007 (#58) so operator queries can split mongo activity from pg
    /// at the audit layer; spec 12 §"Mongo adapter" line 241.
    pub db_type: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit write failed")]
    Write(#[source] sqlx::Error),
    #[error("audit write timed out after {0:?}")]
    Timeout(Duration),
}

/// Persist one audit row. Synchronous on the request path: callers MUST
/// propagate this error to the agent so an unaudited call never succeeds.
/// The write is wrapped in an [`AUDIT_WRITE_TIMEOUT`] deadline so a wedged
/// state DB fails the request instead of hanging the tool response.
pub async fn log(pool: &PgPool, row: &AuditRow) -> Result<(), AuditError> {
    match tokio::time::timeout(AUDIT_WRITE_TIMEOUT, insert_row(pool, row)).await {
        Ok(res) => res,
        Err(_) => Err(AuditError::Timeout(AUDIT_WRITE_TIMEOUT)),
    }
}

async fn insert_row(pool: &PgPool, row: &AuditRow) -> Result<(), AuditError> {
    let groups_json = serde_json::to_value(&row.groups).unwrap_or(serde_json::Value::Array(vec![]));
    // `ON CONFLICT (id) DO NOTHING` makes the write idempotent when the
    // request-path guard fires a fallback insert after a timed-out primary
    // write: even in the (theoretically possible) SQLx-cancellation race
    // where the primary INSERT still commits, the fallback with the same
    // `id` becomes a no-op instead of a duplicate row. Append-only
    // semantics are preserved — we never UPDATE, only skip inserting.
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
        "SELECT id, request_id, user_sub, user_email, groups, tool, server_name, database_name, \
                sql, reason, outcome, elapsed_ms, row_count, truncated, error_message, \
                agent_client, ip, db_type, occurred_at \
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

/// One row in the `get_query_history` response. Field names match the wire
/// contract documented at `website/docs/initial-idea/03-mcp-tools.md`
/// §get_query_history.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub request_id: String,
    pub sql: Option<String>,
    pub reason: Option<String>,
    pub occurred_at: String,
    pub elapsed_ms: Option<i64>,
    pub row_count: Option<i64>,
    pub outcome: String,
}

/// SECURITY-CRITICAL — used by `tools::get_query_history`. Reads
/// `audit_calls` rows for a *single* caller, scoped by the SSO-verified
/// `user_sub` (NOT a client-supplied field — see the caller's
/// `#[serde(deny_unknown_fields)]` Arguments). Filters by server+database
/// so the response is target-scoped. Optional `since` is a pre-parsed
/// `DateTime<Utc>`; `limit` is pre-clamped to `GATEWAY_ROW_LIMIT_CEILING`.
///
/// The composite index `(user_sub, occurred_at DESC)` from migration 0003
/// covers the WHERE + ORDER BY exactly — no separate scan.
pub async fn query_user_history(
    pool: &PgPool,
    user_sub: &str,
    server: &str,
    database: &str,
    since: Option<DateTime<Utc>>,
    limit: u32,
) -> Result<Vec<HistoryEntry>, sqlx::Error> {
    // `$4::timestamptz` so the bind type is unambiguous when `since` is
    // NULL — sqlx otherwise can't tell `TIMESTAMPTZ` from `TEXT`.
    let limit_i64 = i64::from(limit);
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
    .bind(limit_i64)
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
