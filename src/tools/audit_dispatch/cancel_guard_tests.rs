//! Pure-logic tests for the two helpers that decide what a cancellation
//! or post-work drop actually writes. Full state-DB failure integration
//! coverage lives in `tests/audit_dispatch_cancellation_real_db.rs`.

use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::transport::jsonrpc::Response;

fn empty_row() -> AuditRow {
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
        outcome: String::new(),
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".into()),
    }
}

fn outcome_success() -> Outcome {
    Outcome {
        response: Response::result(json!(1), &json!({"ok": true})),
        code: OutcomeCode::Success,
        elapsed_ms: Some(42),
        row_count: Some(3),
        truncated: Some(false),
        error_message: None,
    }
}

/// A drop with no outcome recorded — mid-work disconnect. The row must
/// be tagged `"cancelled"` and get the distinguishing error_message so
/// operators can tell it apart from `"forbidden"` at a glance.
#[test]
fn finalize_dropped_row_stamps_cancelled_when_outcome_empty() {
    let mut row = empty_row();
    finalize_dropped_row(&mut row);
    assert_eq!(row.outcome, "cancelled");
    assert_eq!(
        row.error_message.as_deref(),
        Some("client disconnected before completion")
    );
}

/// A drop AFTER `record_outcome` was called — the tool completed, then
/// the primary `audit::log` failed / was cancelled. The retry must carry
/// the real outcome, not overwrite it with `"cancelled"`.
#[test]
fn finalize_dropped_row_preserves_recorded_outcome() {
    let mut row = empty_row();
    row.outcome = "success".into();
    row.elapsed_ms = Some(42);
    row.error_message = None;
    finalize_dropped_row(&mut row);
    assert_eq!(row.outcome, "success");
    assert_eq!(row.elapsed_ms, Some(42));
    assert_eq!(row.error_message, None);
}

/// A recorded error outcome is preserved too — a failed query whose
/// audit write then fails should still record the failure, not
/// `"cancelled"`.
#[test]
fn finalize_dropped_row_preserves_error_outcome() {
    let mut row = empty_row();
    row.outcome = "forbidden_sql".into();
    row.error_message = Some("statement type `INSERT` is not allowed".into());
    finalize_dropped_row(&mut row);
    assert_eq!(row.outcome, "forbidden_sql");
    assert_eq!(
        row.error_message.as_deref(),
        Some("statement type `INSERT` is not allowed")
    );
}

/// Calls `record_outcome` and asserts every audit-relevant field mirrors
/// the outcome — on the guard's fallback row AND on the returned primary
/// row, which must be identical so the two writes stay idempotent under
/// one `id`.
#[test]
fn record_outcome_mirrors_all_audit_fields_onto_both_rows() {
    let mut guard = CancelledAuditGuard {
        row: empty_row(),
        state_db: None, // no pool: Drop short-circuits, nothing spawns
        tool: "run_query",
        stream_sinks: Vec::new(),
    };
    let primary = guard.record_outcome(&outcome_success());
    for row in [&guard.row, &primary] {
        assert_eq!(row.outcome, "success");
        assert_eq!(row.elapsed_ms, Some(42));
        assert_eq!(row.row_count, Some(3));
        assert_eq!(row.truncated, Some(false));
        assert_eq!(row.error_message, None);
    }
    assert_eq!(guard.row.id, primary.id);
}
