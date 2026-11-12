//! The single chokepoint every tool dispatch flows through: refuses if the
//! state DB is missing (audit unavailable), runs the tool's `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).

mod cancel_guard;
mod code;
mod metric_names;
mod outcome;
mod types;

pub use code::OutcomeCode;
pub use outcome::{ToolErrorMessages, outcome_from_exec_error, success_outcome, tool_success};
// `error_outcome` turns an arbitrary caller-supplied string into both the client
// payload and the audit row's `error_message`. Scope it to the tools that own
// their per-tool wording; callers outside `src/tools/` must go through the
// sanitized `outcome_from_exec_error` boundary instead.
pub(in crate::tools) use outcome::error_outcome;
use outcome::tool_error;
pub use types::{AuditHeader, Outcome, RequestContext};

use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use metrics::{counter, histogram};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::{self, AuditError, AuditRow};
use crate::auth::Identity;
use crate::authz::cache::load_or_empty;
use crate::config::{Grant, StreamSinkConfig};
use crate::tools::ToolCtx;
use crate::transport::jsonrpc::{ErrorObject, Response};

use cancel_guard::CancelledAuditGuard;
use metric_names::{AUDIT_WRITE_DURATION, QUERY_DURATION, TOOL_CALLS};

/// Load the caller's DB grants, then run `work` with them through
/// [`audit_dispatch`]. A grants-load failure still writes an audit row
/// (`internal`) — the work never runs, but the call is accounted for.
pub async fn run_audited<W, Fut>(
    ctx: ToolCtx<'_>,
    id: Value,
    header: AuditHeader<'_>,
    work: W,
) -> Response
where
    W: FnOnce(Value, Arc<Vec<Grant>>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    match load_or_empty(ctx.permissions_cache, ctx.identity).await {
        Ok(grants) => {
            let work = work(id.clone(), grants);
            dispatch_in(ctx, id, header, work).await
        }
        Err(err) => {
            tracing::error!(%err, "permissions cache load failed");
            let outcome = error_outcome(
                id.clone(),
                OutcomeCode::Internal,
                "permissions_cache_load_failed",
            );
            audit_outcome(ctx, id, header, outcome).await
        }
    }
}

/// Audit an outcome decided before any work ran (argument rejections).
pub async fn audit_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    header: AuditHeader<'_>,
    outcome: Outcome,
) -> Response {
    dispatch_in(ctx, id, header, async move { outcome }).await
}

async fn dispatch_in<Fut>(
    ctx: ToolCtx<'_>,
    id: Value,
    header: AuditHeader<'_>,
    work: Fut,
) -> Response
where
    Fut: Future<Output = Outcome>,
{
    audit_dispatch(
        id,
        ctx.identity,
        ctx.state_db,
        ctx.request,
        header,
        &ctx.config.logging.stream,
        work,
    )
    .await
}

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
            TOOL_CALLS,
            "tool" => header.tool,
            "outcome" => OutcomeCode::Unavailable.as_str(),
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
            outcome = OutcomeCode::Unavailable.as_str(),
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
    let mut cancel_guard = CancelledAuditGuard {
        row: pending_row(identity, request_ctx, &header),
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
    let row = cancel_guard.record_outcome(&outcome);

    counter!(
        TOOL_CALLS,
        "tool" => header.tool,
        "outcome" => outcome.code.as_str(),
    )
    .increment(1);
    if let Some(elapsed_ms) = outcome.elapsed_ms {
        histogram!(QUERY_DURATION, "tool" => header.tool).record(elapsed_ms as f64 / 1000.0);
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
        outcome = outcome.code.as_str(),
        duration_ms = outcome.elapsed_ms.unwrap_or(0),
        "tool dispatched"
    );

    let audit_started = Instant::now();
    let audit_result = audit::log(state_db, &row).await;
    histogram!(AUDIT_WRITE_DURATION).record(audit_started.elapsed().as_secs_f64());
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
        // gets a stable per-code payload. Both messages are sanitized: the
        // underlying `sqlx::Error` is only in the tracing event above so a
        // wrapped connection string cannot leak into a client response.
        return match err {
            AuditError::Timeout(_) => tool_error(
                id,
                OutcomeCode::Timeout,
                "audit write timed out; request rejected",
            ),
            AuditError::Write(_) => tool_error(
                id,
                OutcomeCode::Internal,
                "audit write failed; request rejected",
            ),
        };
    }

    // Primary audit landed. Stream fan-out happens only now — never before
    // the durable write succeeds, and never on the error return above (a row
    // that isn't the system of record yet must not be streamed as if it
    // were).
    audit::stream::send(stream_sinks, &row);
    // Release the guard so its Drop is a no-op.
    cancel_guard.disarm();
    outcome.response
}

/// The dispatch's audit row before the work runs: everything known
/// up-front, `outcome` empty until the guard records it. One `id` per
/// dispatch, shared by the primary write and the guard's fallback —
/// `ON CONFLICT (id) DO NOTHING` makes the pair idempotent, so a timed-out
/// primary that commits anyway cannot produce a duplicate row.
fn pending_row(
    identity: &Identity,
    request_ctx: &RequestContext,
    header: &AuditHeader<'_>,
) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: request_ctx.request_id.to_string(),
        user_sub: identity.user_sub.clone(),
        user_email: identity.user_email.clone(),
        groups: identity.groups.clone(),
        tool: header.tool.to_string(),
        server: header.server.map(str::to_string),
        database: header.database.map(str::to_string),
        sql: header.sql.map(str::to_string),
        reason: header.reason.map(str::to_string),
        outcome: String::new(),
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: request_ctx.agent_client.clone(),
        ip: request_ctx.ip.map(|i| i.to_string()),
        db_type: header.db_type.map(str::to_string),
    }
}
