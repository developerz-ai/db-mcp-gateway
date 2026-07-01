//! The single chokepoint every tool dispatch flows through: refuses if the
//! state DB is missing (audit unavailable), runs the tool's `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).
//!
//! Extracted from the original `run_query` so each tool gets the same
//! guarantees without re-implementing the chokepoint.

pub mod outcome;
pub mod types;

pub use outcome::{
    ToolErrorMessages, error_outcome, outcome_from_exec_error, success_outcome, tool_error,
    tool_success,
};
pub use types::{AuditHeader, Outcome, RequestContext};

use std::future::Future;
use std::time::Instant;

use metrics::{counter, histogram};
use serde_json::Value;
use sqlx::PgPool;

use crate::audit::{self, AuditRow};
use crate::auth::Identity;
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
}

impl CancelledAuditGuard {
    fn disarm(mut self) {
        self.row = None;
        self.state_db = None;
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
        row.outcome = "cancelled".to_string();
        // Distinct error_message so operators can tell a cancelled row
        // from a forbidden one when scanning the table at speed.
        row.error_message = Some("client disconnected before completion".to_string());
        counter!(
            METRIC_TOOL_CALLS,
            "tool" => self.tool,
            "outcome" => "cancelled",
        )
        .increment(1);
        // Detached spawn. We can't await it; if it fails, there's no
        // surface to report the failure to — the agent already disconnected.
        // Operator sees the failure in tracing via audit::log's internal
        // error path.
        tokio::spawn(async move {
            if let Err(err) = audit::log(&pool, &row).await {
                tracing::error!(%err, "cancelled audit row write failed");
            }
        });
    }
}

pub async fn audit_dispatch<Fut>(
    id: Value,
    identity: &Identity,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    header: AuditHeader<'_>,
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
            request_id = %id,
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

    // Arm the cancellation guard BEFORE awaiting the work. If `work.await`
    // is dropped (agent disconnect), the guard's `Drop` impl fires and
    // spawns a detached `outcome = "cancelled"` audit write. CLAUDE.md
    // *§Cancellation safety*: "audit row outcome: cancelled."
    //
    // The guard carries a pre-built row so the spawned task doesn't need
    // to re-thread identity / context across the spawn boundary.
    let cancel_guard = CancelledAuditGuard {
        row: Some(AuditRow {
            request_id: id.to_string(),
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
    };
    let outcome = work.await;
    // Work completed normally — release the guard so its Drop is a no-op.
    cancel_guard.disarm();

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
        request_id = %id,
        user_sub = %identity.user_sub,
        tool = %header.tool,
        server = header.server.unwrap_or(""),
        db = header.database.unwrap_or(""),
        outcome = %outcome.code,
        duration_ms = outcome.elapsed_ms.unwrap_or(0),
        "tool dispatched"
    );

    let row = AuditRow {
        request_id: id.to_string(),
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
        tracing::error!(
            %err,
            request_id = %id,
            user_sub = %identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            duration_ms = outcome.elapsed_ms.unwrap_or(0),
            audit_write_duration_ms = audit_started.elapsed().as_millis() as u64,
            "audit write failed; aborting tool response"
        );
        return Response::error(
            id,
            ErrorObject::internal("audit write failed; request rejected"),
        );
    }

    outcome.response
}
