//! Pure-logic tests for what the guard's fallback row carries at each
//! stage. Real state-DB coverage lives in
//! `tests/audit_dispatch_cancellation_real_db.rs` and
//! `tests/audit_two_phase_real_db.rs`.

use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::mcp::jsonrpc::Response;
use crate::tools::audit_dispatch::Reply;

fn row() -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: "req-1".into(),
        user_sub: "user-1".into(),
        user_email: "u@example.com".into(),
        groups: vec!["g".into()],
        tool: "run_query".into(),
        server: Some("srv".into()),
        database: Some("db".into()),
        sql: Some("SELECT 1".into()),
        reason: None,
        outcome: OutcomeCode::Success,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".into()),
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    }
}

/// A guard that never armed a pool: `Drop` short-circuits, nothing spawns,
/// so these tests need no runtime.
fn unarmed_guard() -> CancelledAuditGuard {
    CancelledAuditGuard {
        row: row(),
        completed: false,
        state_db: None,
        tool: "run_query",
        sinks: StreamSinks::default(),
        tasks: DetachedTasks::new(),
    }
}

fn outcome(code: OutcomeCode, error_message: Option<&str>) -> Outcome {
    Outcome {
        reply: Reply::Response(Box::new(Response::result(json!(1), &json!({"ok": true})))),
        code,
        elapsed_ms: Some(42),
        row_count: Some(3),
        truncated: Some(false),
        error_message: error_message.map(str::to_string),
        write: None,
    }
}

/// Every audit field mirrors the outcome — on the guard's fallback row AND
/// on the returned primary row, which share one `id` so the two writes stay
/// idempotent.
#[test]
fn record_outcome_mirrors_all_audit_fields_onto_both_rows() {
    let mut guard = unarmed_guard();
    let primary = guard.record_outcome(&outcome(OutcomeCode::Success, None));
    for row in [&guard.row, &primary] {
        assert_eq!(row.outcome, OutcomeCode::Success);
        assert_eq!(row.elapsed_ms, Some(42));
        assert_eq!(row.row_count, Some(3));
        assert_eq!(row.truncated, Some(false));
        assert_eq!(row.error_message, None);
    }
    assert_eq!(guard.row.id, primary.id);
    assert!(guard.completed);
}

/// After a failed primary write the fallback records the code the client
/// saw; the tool's own outcome and message move to `error_message`.
#[test]
fn audit_failure_records_the_client_code_and_keeps_the_tool_outcome() {
    let mut guard = unarmed_guard();
    guard.record_outcome(&outcome(
        OutcomeCode::ForbiddenSql,
        Some("statement type `INSERT` is not allowed"),
    ));
    guard.record_audit_failure();
    assert_eq!(guard.row.outcome, OutcomeCode::AuditUnavailable);
    assert_eq!(
        guard.row.error_message.as_deref(),
        Some("tool outcome forbidden_sql: statement type `INSERT` is not allowed")
    );

    let mut guard = unarmed_guard();
    guard.record_outcome(&outcome(OutcomeCode::Success, None));
    guard.record_audit_failure();
    assert_eq!(
        guard.row.error_message.as_deref(),
        Some("tool outcome success")
    );
}

/// Armed and dropped mid-work, the row says `cancelled` with the
/// distinguishing message, so operators can tell it from a `forbidden`.
#[tokio::test]
async fn armed_row_reads_cancelled_until_an_outcome_is_recorded() {
    let pool = PgPool::connect_lazy("postgres://unused@localhost/unused").expect("lazy pool");
    let guard = CancelledAuditGuard::arm(
        row(),
        "run_query",
        pool,
        StreamSinks::default(),
        DetachedTasks::new(),
    );
    assert_eq!(guard.row.outcome, OutcomeCode::Cancelled);
    assert_eq!(
        guard.row.error_message.as_deref(),
        Some("client disconnected before completion")
    );
    assert!(!guard.completed);
    guard.disarm();
}
