//! The single chokepoint every tool dispatch flows through: refuses if the
//! state DB is missing (audit unavailable), runs the tool's `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).
//!
//! Extracted from the original `run_query` so each tool gets the same
//! guarantees without re-implementing the chokepoint.

mod outcome;
mod types;

pub use outcome::{ToolErrorMessages, outcome_from_exec_error, success_outcome, tool_success};
// `error_outcome` turns an arbitrary caller-supplied string into both the client
// payload and the audit row's `error_message`. Scope it to the tools that own
// their per-tool wording; callers outside `src/tools/` must go through the
// sanitized `outcome_from_exec_error` boundary instead.
pub(in crate::tools) use outcome::error_outcome;
use outcome::tool_error;
pub use types::{AuditHeader, Outcome, RequestContext};

use std::future::Future;
use std::time::Instant;

use metrics::{counter, histogram};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::{self, AuditError, AuditRow};
use crate::auth::Identity;
use crate::config::StreamSinkConfig;
use crate::transport::jsonrpc::{ErrorObject, Response};

/// Per-call counter — `tool` is the tool name, `outcome` is the spec 03 code
/// (`success`/`forbidden`/`timeout`/…). Both labels are bounded.
const METRIC_TOOL_CALLS: &str = "tool_calls";
/// Wall-clock the tool's own work took (from the `Outcome.elapsed_ms` the tool
/// reports). Excludes the audit write — that has its own histogram.
const METRIC_QUERY_DURATION: &str = "query_duration_seconds";
/// Wall-clock the synchronous audit insert took. Spec calls audit-write a
/// hot-path concern; this is the metric the alert in #22 will fire on.
const METRIC_AUDIT_WRITE_DURATION: &str = "audit_write_duration_seconds";

/// Drop-fired guard that writes a `"cancelled"` audit row if the dispatch
/// future is dropped before `disarm()` is called. The detached
/// `tokio::spawn` lets the audit write outlive the cancellation.
///
/// Why this shape: when an agent disconnects, axum drops the handler
/// future, which drops the in-flight `audit_dispatch` future mid-`.await`.
/// Without a guard, the audit row is never written. We can't use async
/// `Drop` (doesn't exist in Rust today), so we spawn the write on the
/// runtime instead — the spawned task runs to completion independently
/// of the parent future's lifecycle.
///
/// Server-side query cancellation is handled separately, in the exec layer:
/// `PgAdapter` captures the backend PID and fires `pg_cancel_backend` from a
/// detached task on drop, because dropping a `sqlx::Transaction` only closes
/// the socket — it does NOT stop the query already running on the backend.
/// (Mongo relies on `maxTimeMS` plus cursor-drop.) This guard's only job is
/// the audit row.
struct CancelledAuditGuard {
    /// `Some` until `disarm()` is called. On `Drop` we spawn a detached
    /// write of this row with `outcome = "cancelled"`.
    row: Option<AuditRow>,
    /// Cloned pool handle — needed inside the spawned task. `PgPool` is
    /// `Arc`-internally so cloning is cheap.
    state_db: Option<PgPool>,
    /// Tool name kept separately for the metric counter emitted from the
    /// drop path (audit row's `tool` field is moved into the spawn).
    tool: &'static str,
    /// Owned copy — the spawned task outlives the borrow `audit_dispatch`
    /// holds. Cheap: at most a handful of enum variants.
    stream_sinks: Vec<StreamSinkConfig>,
}

impl CancelledAuditGuard {
    fn disarm(mut self) {
        self.row = None;
        self.state_db = None;
    }

    /// Record the tool's actual outcome on the pre-built row. Called after
    /// `work.await` completes so the guard's fallback write — fired if the
    /// dispatch future is dropped or the primary `audit::log` fails — carries
    /// the real outcome rather than the placeholder `"cancelled"` that
    /// `finalize_dropped_row` falls back to when the outcome was never set.
    fn record_outcome(&mut self, outcome: &Outcome) {
        if let Some(row) = self.row.as_mut() {
            row.outcome = outcome.code.to_string();
            row.elapsed_ms = outcome.elapsed_ms;
            row.row_count = outcome.row_count;
            row.truncated = outcome.truncated;
            row.error_message = outcome.error_message.clone();
        }
    }
}

/// If the tool never got to set an outcome, the drop is firing mid-work —
/// the true outcome is unknown, so tag it `"cancelled"` and stamp the
/// error_message so operators can distinguish it from a forbidden row at a
/// glance. If the outcome IS set, the drop is firing AFTER work completed
/// (the primary `audit::log` failed, timed out, or the future was dropped
/// mid-audit) and the real outcome must be preserved for the retry.
fn finalize_dropped_row(row: &mut AuditRow) {
    if row.outcome.is_empty() {
        row.outcome = "cancelled".to_string();
        row.error_message = Some("client disconnected before completion".to_string());
    }
}

impl Drop for CancelledAuditGuard {
    fn drop(&mut self) {
        let Some(mut row) = self.row.take() else {
            return;
        };
        let Some(pool) = self.state_db.take() else {
            return;
        };
        // If the outcome was already recorded, `audit_dispatch` already
        // emitted the primary METRIC_TOOL_CALLS increment at line ~215.
        // Emitting it again here would double-count every audit-failure
        // path. Only count in Drop for the mid-work cancellation branch
        // where `finalize_dropped_row` promotes the empty outcome to
        // `"cancelled"` and no primary increment ever ran.
        let outcome_was_recorded = !row.outcome.is_empty();
        finalize_dropped_row(&mut row);
        if !outcome_was_recorded {
            counter!(
                METRIC_TOOL_CALLS,
                "tool" => self.tool,
                "outcome" => row.outcome.clone(),
            )
            .increment(1);
        }
        // Detached spawn. We can't await it; if it fails, there's no
        // surface to report the failure to — the agent already disconnected
        // (or the primary write already returned an error the caller saw).
        // Operator sees the failure in tracing via audit::log's internal
        // error path. `audit::log` has its own timeout so a wedged state DB
        // does not stall the detached task forever. The row shares `id`
        // with any prior primary write, so `ON CONFLICT (id) DO NOTHING`
        // in `insert_row` makes this second attempt idempotent.
        let stream_sinks = self.stream_sinks.clone();
        tokio::spawn(async move {
            match audit::log(&pool, &row).await {
                Ok(()) => audit::stream::send(&stream_sinks, &row),
                Err(err) => tracing::error!(%err, "fallback audit row write failed"),
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn audit_dispatch<Fut>(
    id: Value,
    identity: &Identity,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    header: AuditHeader<'_>,
    stream_sinks: &[StreamSinkConfig],
    work: Fut,
) -> Response
where
    Fut: Future<Output = Outcome>,
{
    let Some(state_db) = state_db else {
        counter!(
            METRIC_TOOL_CALLS,
            "tool" => header.tool,
            "outcome" => "unavailable",
        )
        .increment(1);
        // Contract (issue #14): exactly one dispatch line per call, even when
        // we refuse before running the tool. `duration_ms = 0` because no
        // tool work happened.
        tracing::info!(
            request_id = %request_ctx.request_id,
            user_sub = %identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            outcome = "unavailable",
            duration_ms = 0_i64,
            "tool dispatched"
        );
        return Response::error(
            id,
            ErrorObject::internal(format!(
                "audit log unavailable — refusing to dispatch {}",
                header.tool
            )),
        );
    };

    // One audit-row primary key per dispatch, shared between the guard's
    // fallback row and the primary write below. Combined with
    // `ON CONFLICT (id) DO NOTHING` in `audit::insert_row`, this makes the
    // primary + fallback pair idempotent — a timed-out primary that ends
    // up committing anyway cannot produce a duplicate row when the guard's
    // detached spawn retries.
    let audit_id = Uuid::new_v4();

    // Arm the cancellation guard BEFORE awaiting the work. If `work.await`
    // is dropped (agent disconnect), the guard's `Drop` impl fires and
    // spawns a detached `outcome = "cancelled"` audit write. CLAUDE.md
    // *§Cancellation safety*: "audit row outcome: cancelled."
    //
    // The guard carries a pre-built row so the spawned task doesn't need
    // to re-thread identity / context across the spawn boundary.
    let mut cancel_guard = CancelledAuditGuard {
        row: Some(AuditRow {
            id: audit_id,
            request_id: request_ctx.request_id.to_string(),
            user_sub: identity.user_sub.clone(),
            user_email: identity.user_email.clone(),
            groups: identity.groups.clone(),
            tool: header.tool.to_string(),
            server: header.server.map(str::to_string),
            database: header.database.map(str::to_string),
            sql: header.sql.map(str::to_string),
            reason: header.reason.map(str::to_string),
            outcome: String::new(), // overwritten in Drop
            elapsed_ms: None,       // unknown — work was cancelled
            row_count: None,
            truncated: None,
            error_message: None, // set in Drop
            agent_client: request_ctx.agent_client.clone(),
            ip: request_ctx.ip.map(|i| i.to_string()),
            db_type: header.db_type.map(str::to_string),
        }),
        state_db: Some(state_db.clone()),
        tool: header.tool,
        stream_sinks: stream_sinks.to_vec(),
    };
    let outcome = work.await;
    // Work completed — mirror the outcome onto the guard's row so that if
    // the future is dropped during the audit write below (or the write
    // itself fails), the guard's detached fallback carries the actual
    // outcome rather than the placeholder `"cancelled"`. Guard stays armed
    // until the primary write succeeds — closing the window between "tool
    // ran" and "row landed" that used to let a wedged state DB + client
    // disconnect leave the tool call with zero audit rows.
    cancel_guard.record_outcome(&outcome);

    counter!(
        METRIC_TOOL_CALLS,
        "tool" => header.tool,
        "outcome" => outcome.code,
    )
    .increment(1);
    if let Some(elapsed_ms) = outcome.elapsed_ms {
        histogram!(METRIC_QUERY_DURATION, "tool" => header.tool).record(elapsed_ms as f64 / 1000.0);
    }

    // Single per-dispatch log line carrying the documented field contract
    // (issue #14): request_id, user_sub, tool, server, db, outcome,
    // duration_ms. Lives at the chokepoint so every tool gets it without
    // per-tool code. `server` + `db` together fully scope the call per spec
    // 03; emitting only `db` makes correlation ambiguous across servers.
    tracing::info!(
        request_id = %request_ctx.request_id,
        user_sub = %identity.user_sub,
        tool = %header.tool,
        server = header.server.unwrap_or(""),
        db = header.database.unwrap_or(""),
        outcome = %outcome.code,
        duration_ms = outcome.elapsed_ms.unwrap_or(0),
        "tool dispatched"
    );

    let row = AuditRow {
        id: audit_id,
        request_id: request_ctx.request_id.to_string(),
        user_sub: identity.user_sub.clone(),
        user_email: identity.user_email.clone(),
        groups: identity.groups.clone(),
        tool: header.tool.to_string(),
        server: header.server.map(str::to_string),
        database: header.database.map(str::to_string),
        sql: header.sql.map(str::to_string),
        reason: header.reason.map(str::to_string),
        outcome: outcome.code.to_string(),
        elapsed_ms: outcome.elapsed_ms,
        row_count: outcome.row_count,
        truncated: outcome.truncated,
        error_message: outcome.error_message,
        agent_client: request_ctx.agent_client.clone(),
        ip: request_ctx.ip.map(|i| i.to_string()),
        db_type: header.db_type.map(str::to_string),
    };
    let audit_started = Instant::now();
    let audit_result = audit::log(state_db, &row).await;
    histogram!(METRIC_AUDIT_WRITE_DURATION).record(audit_started.elapsed().as_secs_f64());
    if let Err(err) = audit_result {
        // Don't embed the underlying error string in the response (could leak
        // DB connection details on some sqlx error paths). Operator sees the
        // chained source via the tracing event.
        //
        // `duration_ms` keeps the same contract as the success log: wall-clock
        // the tool itself took. The audit-insert latency is a separate field
        // (`audit_write_duration_ms`) so consumers comparing dispatch lines
        // across success/failure don't see two different semantics.
        //
        // NOTE: guard stays armed on this path. Its detached Drop attempt is
        // defense-in-depth against a transient state DB blip and carries the
        // real outcome (see `record_outcome` above). We already told the
        // caller the request failed, so the retry's success or failure is
        // operator-visible via tracing only.
        tracing::error!(
            %err,
            request_id = %request_ctx.request_id,
            user_sub = %identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            duration_ms = outcome.elapsed_ms.unwrap_or(0),
            audit_write_duration_ms = audit_started.elapsed().as_millis() as u64,
            "audit write failed; aborting tool response"
        );
        // Route through the tool_error shape (spec 03 §Errors) so the client
        // gets a stable per-code payload. `AuditError::Timeout` surfaces as
        // `"timeout"` — the same code the tool layer uses for a wedged
        // target-DB — and `AuditError::Write` maps to `"internal"`. Both
        // messages are sanitized: the underlying `sqlx::Error` is only in
        // the tracing event above so a wrapped connection string cannot
        // leak into a client response.
        return match err {
            AuditError::Timeout(_) => {
                tool_error(id, "timeout", "audit write timed out; request rejected")
            }
            AuditError::Write(_) => {
                tool_error(id, "internal", "audit write failed; request rejected")
            }
        };
    }

    // Primary audit landed. Stream fan-out happens only now — never before
    // the durable write succeeds, and never on this function's error return
    // above (a row that isn't the system of record yet must not be streamed
    // as if it were).
    audit::stream::send(stream_sinks, &row);
    // Release the guard so its Drop is a no-op.
    cancel_guard.disarm();
    outcome.response
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests for the two helpers that decide what a cancellation
    //! or post-work drop actually writes. Full state-DB failure integration
    //! coverage lives in `tests/audit_dispatch_cancellation_real_db.rs`.

    use super::*;
    use crate::transport::jsonrpc::Response;
    use serde_json::json;

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
            code: "success",
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

    /// Builds a guard with an empty-outcome row, calls `record_outcome`,
    /// and asserts every audit-relevant field on the guard's row mirrors
    /// the outcome. This is the property the reorder relies on: if the
    /// future is dropped after `record_outcome` but before `disarm`, the
    /// fallback write must carry these values.
    #[test]
    fn record_outcome_mirrors_all_audit_fields_onto_guard_row() {
        let mut guard = CancelledAuditGuard {
            row: Some(empty_row()),
            state_db: None, // no pool needed for this pure test
            tool: "run_query",
            stream_sinks: Vec::new(),
        };
        let out = outcome_success();
        guard.record_outcome(&out);
        let row = guard.row.as_ref().expect("row still armed");
        assert_eq!(row.outcome, "success");
        assert_eq!(row.elapsed_ms, Some(42));
        assert_eq!(row.row_count, Some(3));
        assert_eq!(row.truncated, Some(false));
        assert_eq!(row.error_message, None);
        // Neutralise the guard's Drop for the test — no state_db was set, so
        // Drop's `let Some(pool) = ...` short-circuits and nothing spawns.
    }

    /// `record_outcome` on a disarmed guard is a no-op (defensive: the
    /// dispatch function only calls it while armed, but the guard's own
    /// contract should not panic if the invariant is ever relaxed).
    #[test]
    fn record_outcome_on_disarmed_guard_is_noop() {
        let mut guard = CancelledAuditGuard {
            row: None,
            state_db: None,
            tool: "run_query",
            stream_sinks: Vec::new(),
        };
        guard.record_outcome(&outcome_success());
        assert!(guard.row.is_none());
    }
}
