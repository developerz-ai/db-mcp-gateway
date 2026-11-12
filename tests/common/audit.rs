//! Audit-row lookups. CLAUDE.md non-negotiable: every tool dispatch produces
//! an `audit_calls` row, so every tool test asserts one through here.

use db_mcp_gateway::audit::{AuditRow, latest_for_user_tool};
use sqlx::PgPool;

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
