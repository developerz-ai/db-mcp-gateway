//! The single chokepoint every tool dispatch flows through: runs the tool's
//! `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).
//! Tools that reach a target DB also commit an intent row first
//! ([`crate::tools::target::record_intent`]), so a crash between the target
//! call and this row still leaves a trace the reaper turns into `abandoned`.

mod cancel_guard;
mod metric_names;
mod outcome;
mod types;

pub use crate::audit::OutcomeCode;
pub use outcome::{ToolErrorMessages, outcome_from_exec_error, success_outcome, tool_success};
// `error_outcome` turns an arbitrary caller-supplied string into both the client
// payload and the audit row's `error_message`. Scope it to the tools that own
// their per-tool wording; callers outside `src/tools/` must go through the
// sanitized `outcome_from_exec_error` boundary instead.
use outcome::tool_error;
pub(in crate::tools) use outcome::{error_outcome, invalid_arguments};
pub use types::{
    AuditHeader, AuditStore, Outcome, Reply, RequestContext, Upstream, UpstreamClaim, WriteEffect,
};

use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use metrics::{counter, histogram};
use serde_json::Value;
use uuid::Uuid;

use crate::audit::{self, AuditRow};
use crate::auth::Identity;
use crate::config::Grant;
use crate::mcp::jsonrpc::Response;
use crate::tools::ToolCtx;

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
    match ctx.permissions_cache.get_for(ctx.identity).await {
        Ok(grants) => {
            let work = work(id.clone(), grants);
            dispatch_in(ctx, id, header, work).await
        }
        Err(err) => {
            tracing::error!(%err, "permissions cache load failed");
            let outcome = error_outcome(OutcomeCode::Internal, "permissions_cache_load_failed");
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

/// Audit a call whose arguments did not parse: `invalid_arguments`, no
/// target, the JSON-RPC `invalid_params` envelope on the wire.
pub async fn reject_arguments(
    ctx: ToolCtx<'_>,
    id: Value,
    tool: &'static str,
    message: &str,
) -> Response {
    let outcome = invalid_arguments(id.clone(), message);
    audit_outcome(ctx, id, AuditHeader::untargeted(tool), outcome).await
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
    let store = AuditStore {
        pool: ctx.state_db,
        sinks: ctx.audit_sinks,
        tasks: ctx.detached,
    };
    audit_dispatch(id, ctx.identity, ctx.request, header, store, work).await
}

pub async fn audit_dispatch<Fut>(
    id: Value,
    identity: &Identity,
    request_ctx: &RequestContext,
    header: AuditHeader<'_>,
    store: AuditStore<'_>,
    work: Fut,
) -> Response
where
    Fut: Future<Output = Outcome>,
{
    let state_db = store.pool;
    // Armed BEFORE awaiting the work: if `work.await` is dropped (agent
    // disconnect), the guard's `Drop` writes a `cancelled` row. It stays
    // armed until the primary write lands, so a failed or dropped primary
    // write is retried with whatever the guard last recorded.
    let mut guard = CancelledAuditGuard::arm(
        pending_row(identity, request_ctx, &header),
        header.tool,
        state_db.clone(),
        store.sinks.clone(),
        store.tasks.clone(),
    );
    let outcome = work.await;
    let row = guard.record_outcome(&outcome);
    let duration_ms = outcome.elapsed_ms.unwrap_or(0);
    if let Some(elapsed_ms) = outcome.elapsed_ms {
        histogram!(QUERY_DURATION, "tool" => header.tool).record(elapsed_ms as f64 / 1000.0);
    }

    let audit_started = Instant::now();
    let written = audit::log(state_db, &row).await;
    histogram!(AUDIT_WRITE_DURATION).record(audit_started.elapsed().as_secs_f64());
    if let Err(err) = written {
        // `class`, never the sqlx error's text: that can carry connection
        // details. `duration_ms` stays the tool's own time; the audit insert
        // has its own field.
        tracing::error!(
            %err,
            class = %err.class(),
            request_id = %request_ctx.request_id,
            user_sub = %identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            tool_outcome = outcome.code.as_str(),
            duration_ms,
            audit_write_duration_ms = audit_started.elapsed().as_millis() as u64,
            "audit write failed; aborting tool response"
        );
        // The guard stays armed: its fallback retries the row on the
        // detached set, now carrying the code the client is about to see.
        guard.record_audit_failure();
        record_dispatch(
            identity,
            request_ctx,
            &header,
            &outcome,
            OutcomeCode::AuditUnavailable,
        );
        return tool_error(
            id,
            request_ctx.request_id,
            OutcomeCode::AuditUnavailable,
            "audit write failed; request rejected",
        );
    }

    record_dispatch(identity, request_ctx, &header, &outcome, outcome.code);
    // Streamed only now — a row that isn't the system of record yet must
    // not be streamed as if it were.
    store.sinks.send(&row, store.tasks);
    guard.disarm();
    match outcome.reply {
        Reply::Response(response) => *response,
        Reply::ToolError => tool_error(
            id,
            request_ctx.request_id,
            outcome.code,
            outcome.error_message.as_deref().unwrap_or_default(),
        ),
    }
}

/// The per-call counter and the single "tool dispatched" line (issue #14
/// field contract), both carrying `code` — the outcome the client saw.
/// `upstream_*` are the caller's unverified claims, logged for correlation.
fn record_dispatch(
    identity: &Identity,
    request_ctx: &RequestContext,
    header: &AuditHeader<'_>,
    outcome: &Outcome,
    code: OutcomeCode,
) {
    let access = if outcome.write.is_some() {
        "write"
    } else {
        "read"
    };
    counter!(
        TOOL_CALLS,
        "tool" => header.tool,
        "outcome" => code.as_str(),
        "access" => access,
    )
    .increment(1);
    tracing::info!(
        request_id = %request_ctx.request_id,
        user_sub = %identity.user_sub,
        tool = %header.tool,
        server = header.server.unwrap_or(""),
        db = header.database.unwrap_or(""),
        outcome = code.as_str(),
        access,
        duration_ms = outcome.elapsed_ms.unwrap_or(0),
        upstream_run_id = request_ctx.upstream.run_id(),
        upstream_actor = request_ctx.upstream.actor(),
        "tool dispatched"
    );
}

/// The dispatch's audit row before the work runs: everything known
/// up-front. One `id` per dispatch, shared by the primary write and the
/// guard's fallback — `ON CONFLICT (id) DO NOTHING` makes the pair
/// idempotent, so a timed-out primary that commits anyway cannot produce a
/// duplicate row.
fn pending_row(
    identity: &Identity,
    request_ctx: &RequestContext,
    header: &AuditHeader<'_>,
) -> AuditRow {
    let (sql, sql_truncated) = match header.sql.map(audit::cap_stored_sql) {
        Some((sql, truncated)) => (Some(sql), truncated),
        None => (None, false),
    };
    AuditRow {
        id: Uuid::new_v4(),
        request_id: request_ctx.request_id.to_string(),
        user_sub: identity.user_sub.clone(),
        user_email: identity.user_email.clone(),
        groups: identity.groups.clone(),
        tool: header.tool.to_string(),
        server: header.server.map(str::to_string),
        database: header.database.map(str::to_string),
        sql,
        reason: header.reason.map(str::to_string),
        outcome: OutcomeCode::Cancelled,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: request_ctx.agent_client.clone(),
        ip: request_ctx.ip.map(|i| i.to_string()),
        db_type: header.db_type.map(str::to_string),
        upstream_actor: request_ctx.upstream.actor().map(str::to_string),
        upstream_run_id: request_ctx.upstream.run_id().map(str::to_string),
        rows_affected: None,
        sql_truncated,
    }
}
