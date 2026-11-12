//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit` + `truncated` flag).
//!
//! Audit + response envelope are handled by `tools::audit_dispatch` — this
//! file only does the compute step.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Action, Grant, ServerKind};
use crate::exec::ExecQuery;
use crate::exec::sql_guard;
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, error_outcome, outcome_from_exec_error,
    reject_arguments, run_audited, success_outcome,
};
use super::target::{effective_row_limit, ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = "run_query";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "query exceeded the configured statement_timeout",
    sql_rejected: "the target DB rejected the SQL",
    forbidden_prefix: "query",
};

/// Hard floor on result rows when no grant constraint and no caller limit
/// apply. Spec 03 §"Results are size-capped".
const DEFAULT_ROW_LIMIT: u32 = 1000;

#[derive(Debug, Deserialize)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub sql: String,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuccessPayload<'a> {
    columns: &'a [String],
    rows: &'a [Vec<Value>],
    truncated: bool,
    elapsed_ms: u64,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match arguments.map(serde_json::from_value::<Arguments>) {
        Some(Ok(a)) => a,
        _ => {
            return reject_arguments(
                ctx,
                id,
                TOOL_NAME,
                "run_query requires `server`, `database`, `sql` arguments",
            )
            .await;
        }
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: Some(&args.sql),
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, args).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    args: &Arguments,
) -> Outcome {
    // Constraints come from the read-level merge: it matches *every* grant that
    // applies to this (server, db) — `query_write` included, since it implies
    // `query_read` — so the most-restrictive value across all of them always
    // wins, and a write can never dodge a tighter read grant's caps.
    let Some(target) = resolve_target(
        ctx,
        db_grants,
        Action::QueryRead,
        &args.server,
        &args.database,
    ) else {
        return forbidden();
    };
    let (server, database, constraints) = (target.server, target.database, &target.constraints);

    // A separate `query_write` check decides whether data writes are permitted.
    // Only `query_write` grants satisfy it (`query_read` does not imply write),
    // so read-only callers stay on the read-only guard.
    let writes_allowed = resolve_target(
        ctx,
        db_grants,
        Action::QueryWrite,
        &server.name,
        &database.name,
    )
    .is_some();
    let access = if writes_allowed {
        sql_guard::Access::ReadWrite
    } else {
        sql_guard::Access::ReadOnly
    };

    if let Err(rejected) = ensure_reason(constraints, args.reason.as_deref()) {
        return *rejected;
    }

    // Defense-in-depth on top of the DB role: reject anything the grant doesn't
    // cover before it hits the pool. Read-only callers get `is_read_only`;
    // `query_write` callers additionally get single-statement INSERT/UPDATE/
    // DELETE — never schema mods. See exec::sql_guard.
    //
    // pg only: `sql_guard` is a SQL parser; mongo commands are JSON-shaped
    // BSON, not SQL. `MongoAdapter::execute` runs its own read-only
    // rejector (`src/exec/mongo/rejector.rs`) as the equivalent guard. Mongo
    // writes are not offered here — a `query_write` grant on a mongo DB still
    // hits the read-only rejector.
    if matches!(server.kind, ServerKind::Postgres)
        && let Err(err) = sql_guard::check_sql(&args.sql, access)
    {
        return error_outcome(
            OutcomeCode::ForbiddenSql,
            &format!("SQL rejected by gateway: {err}"),
        );
    }

    let row_limit = effective_row_limit(args.limit, constraints.row_limit, DEFAULT_ROW_LIMIT);
    let timeout_ms = constraints.statement_timeout_ms;

    // Emit `request_id` explicitly. The production formatter (main.rs) sets
    // `with_current_span(false)` + `with_span_list(false)`, so span fields
    // from the enclosing `tool_dispatch` span never render — every event
    // that needs to correlate with a Loki log line or audit row has to
    // carry `request_id` on itself. The chokepoint's "tool dispatched"
    // line does; so must this one.
    tracing::info!(
        request_id = %ctx.request.request_id,
        user_sub = %ctx.identity.user_sub,
        server = %server.name,
        db = %database.name,
        row_limit,
        timeout_ms = ?timeout_ms,
        "tool.run_query.dispatch"
    );

    if let Err(refused) = record_intent(ctx, TOOL_NAME, &target, access).await {
        return *refused;
    }

    // Start the wall clock BEFORE pool open so error paths (timeout,
    // unavailable, syntax_error) still surface `duration_ms` in the audit
    // row — spec 07 requires it for every tool invocation.
    let started = Instant::now();
    let adapter = match ctx.registry.get_or_open(server, database).await {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };

    let query = ExecQuery {
        sql: &args.sql,
        binds: &[],
        statement_timeout_ms: timeout_ms,
        row_limit,
        access,
    };
    match adapter.execute(query).await {
        Ok(result) => {
            let elapsed = i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX);
            let row_count = i64::try_from(result.rows.len()).unwrap_or(i64::MAX);
            let truncated = result.truncated;
            let payload = SuccessPayload {
                columns: &result.columns,
                rows: &result.rows,
                truncated,
                elapsed_ms: result.elapsed_ms,
            };
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => {
                    return error_outcome(OutcomeCode::Internal, "failed to serialize result");
                }
            };
            success_outcome(id, text, Some(elapsed), Some(row_count), Some(truncated))
        }
        Err(err) => outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    }
}
