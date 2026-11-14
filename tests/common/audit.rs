//! Audit-row lookups. CLAUDE.md non-negotiable: every tool dispatch produces
//! an `audit_calls` row, so every tool test asserts one through here.

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::audit::stream::StreamSinks;
use db_mcp_gateway::audit::{AuditRow, latest_for_user_tool};
use db_mcp_gateway::config::StreamSinkConfig;
use db_mcp_gateway::tools::audit_dispatch::AuditStore;
use sqlx::PgPool;

/// Reaper sweeps and pruner runs are table-wide: one test's sweep would
/// settle, or its prune delete, another test's backdated rows mid-assertion.
/// Every test that sweeps or prunes holds this for its whole body.
pub static SWEEPS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The caller's latest `tool` row, if any.
pub async fn find_audit(pool: &PgPool, user_sub: &str, tool: &str) -> Option<AuditRow> {
    latest_for_user_tool(pool, user_sub, tool)
        .await
        .expect("audit lookup query runs")
}

/// The caller's latest `tool` row; panics naming `label` when the request
/// went unaudited.
pub async fn latest_audit(pool: &PgPool, user_sub: &str, tool: &str, label: &str) -> AuditRow {
    find_audit(pool, user_sub, tool)
        .await
        .unwrap_or_else(|| panic!("no audit row for `{label}` — request was unaudited"))
}

/// Assert the caller's latest `tool` row exists and carries `expected`.
pub async fn assert_audit_outcome(
    pool: &PgPool,
    user_sub: &str,
    tool: &str,
    expected: &str,
    label: &str,
) {
    let row = latest_audit(pool, user_sub, tool, label).await;
    assert_eq!(
        row.outcome, expected,
        "`{label}` audit outcome (got {})",
        row.outcome
    );
}

/// Owned stream sinks and detached-task set for tests that drive
/// `audit_dispatch` directly instead of through a booted gateway.
pub struct DispatchSinks {
    pub sinks: StreamSinks,
    pub tasks: DetachedTasks,
}

impl DispatchSinks {
    pub fn new(config: &[StreamSinkConfig]) -> Self {
        Self {
            sinks: StreamSinks::from_config(config),
            tasks: DetachedTasks::new(),
        }
    }

    pub fn store<'a>(&'a self, pool: &'a PgPool) -> AuditStore<'a> {
        AuditStore {
            pool,
            sinks: &self.sinks,
            tasks: &self.tasks,
        }
    }
}

/// `access` of the intent row for `request_id`, if one was written.
pub async fn find_intent(pool: &PgPool, request_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT access FROM audit_call_intents WHERE request_id = $1")
        .bind(request_id)
        .fetch_optional(pool)
        .await
        .expect("intent lookup query runs")
}

/// Every `audit_calls` row for `request_id`, oldest first, as
/// `(outcome, error_message)`.
pub async fn calls_for_request(pool: &PgPool, request_id: &str) -> Vec<(String, Option<String>)> {
    sqlx::query_as(
        "SELECT outcome, error_message FROM audit_calls \
         WHERE request_id = $1 ORDER BY occurred_at",
    )
    .bind(request_id)
    .fetch_all(pool)
    .await
    .expect("audit_calls lookup query runs")
}
