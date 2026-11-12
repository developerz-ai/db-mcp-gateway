//! Audit log writer.
//!
//! Spec: website/docs/initial-idea/07-logging-retention.md. CLAUDE.md
//! non-negotiable: every tool dispatch traces to an SSO-verified identity →
//! audit row, and audit-write failures **fail the request**. No best-effort.
//!
//! Two-phase: [`intent`] commits a row before a call reaches a target DB,
//! [`log`] writes the completion row after it, and [`reaper`] turns an intent
//! that never got a completion into an `abandoned` row. Retention lives in
//! [`pruner`], stream sinks in [`stream`] (`stdout` and `syslog`; `otlp` and
//! the archive tier remain out of scope, #218), and the shutdown drain for
//! detached writes in [`drain`].

pub mod drain;
mod history;
pub mod intent;
mod outcome;
pub mod permissions;
pub mod pruner;
pub mod reaper;
pub mod stream;

pub(crate) use history::prefix_at_char_boundary;
pub use history::{
    HISTORY_SQL_MAX_BYTES, HistoryCursor, HistoryEntry, HistoryPage, HistoryQuery, InvalidCursor,
    cap_history_sql,
};
pub use intent::CallIntent;
pub use outcome::OutcomeCode;

use sqlx::PgPool;
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
///
/// `Serialize` backs `audit::stream`'s network sinks (syslog's MSG body) —
/// this is exactly what's already durable in `audit_calls`, nothing more.
#[derive(Debug, Clone, serde::Serialize)]
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
    /// What the call read or ran: the agent's SQL for `run_query`/`explain`,
    /// the target `schema.table` for `sample_table`/`describe_schema`.
    /// `None` for tools that touch no table (`list_servers`, …).
    pub sql: Option<String>,
    pub reason: Option<String>,
    /// `success` or the spec 03 error code the client saw.
    pub outcome: OutcomeCode,
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

impl AuditError {
    /// Credential-free cause for logs: the sqlx error's `Display` can carry
    /// connection details, its class cannot.
    pub fn class(&self) -> String {
        match self {
            Self::Write(source) => crate::state::connect_error_class(source),
            Self::Timeout(_) => "timeout".to_owned(),
        }
    }
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
    crate::state::audit::insert_call(pool, row)
        .await
        .map_err(AuditError::Write)
}

/// Convenience read for tests. Looks up the most recent audit row for a
/// given (user_sub, tool). Not part of the production surface.
#[cfg(any(test, debug_assertions))]
pub async fn latest_for_user_tool(
    pool: &PgPool,
    user_sub: &str,
    tool: &str,
) -> Result<Option<AuditRow>, AuditError> {
    crate::state::audit::latest_call_for_user_tool(pool, user_sub, tool)
        .await
        .map_err(AuditError::Write)
}
