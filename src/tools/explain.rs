//! `explain` — `EXPLAIN (FORMAT JSON)` wrapper. Returns the query plan;
//! plain EXPLAIN never executes the user's statement.
//!
//! Same authz / audit / AST-guard path as `run_query`: the inner SQL is gated
//! through `GuardedSql::parse` at the caller's grant level, so a data write
//! can be explained only under a `query_write` grant (it is planned as the
//! write role). `analyze: true` does execute the statement, so it is refused
//! for anything but a read; the read runs inside the read-only transaction
//! and the statement timeout.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Action, Grant, ServerKind};
use crate::exec::{Access, ExplainQuery, GuardedSql, QueryParam};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, WriteEffect, WriteState, audit_outcome,
    error_outcome, guard_rejected, invalid_arguments, outcome_from_exec_error, reject_arguments,
    run_audited_with_params, success_outcome,
};
use super::query_params::parse_params;
use super::target::{ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = "explain";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "EXPLAIN exceeded the configured statement_timeout",
    sql_rejected: "the target DB rejected the SQL",
    forbidden_prefix: "EXPLAIN",
};
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub sql: String,
    /// Execute the statement for real timings — read statements only.
    #[serde(default)]
    pub analyze: bool,
    #[serde(default)]
    pub reason: Option<String>,
    /// Values bound to `$1..$n`, as in `run_query`.
    #[serde(default)]
    pub params: Vec<Value>,
}

const ANALYZE_NEEDS_READ: &str =
    "SQL rejected by gateway: `analyze` executes the statement; only a read may be analyzed";

#[derive(Debug, Serialize)]
struct SuccessPayload {
    /// The Postgres query plan as a JSON value (passed through verbatim from
    /// `EXPLAIN (FORMAT JSON)`'s single text column).
    plan: Value,
    /// Cost, row estimate, sequential scans and node count read off `plan`;
    /// absent when the plan has no root node.
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<PlanSummary>,
    elapsed_ms: u64,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        // Audit the *user's* SQL, not the EXPLAIN-wrapped one — operators
        // see what the agent asked for.
        sql: Some(&args.sql),
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };
    let params = match parse_params(&args.params) {
        Ok(params) => params,
        Err(message) => {
            let outcome = invalid_arguments(id.clone(), &message);
            return audit_outcome(ctx, id, header, outcome).await;
        }
    };
    let (args, params) = (&args, &params);
    let stored = (!args.params.is_empty()).then_some(args.params.as_slice());
    run_audited_with_params(ctx, id, header, stored, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args, params).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
    params: &[QueryParam],
) -> Outcome {
    let Some(target) = resolve_target(
        ctx,
        db_grants,
        Action::QueryRead,
        &args.server,
        &args.database,
    ) else {
        return forbidden();
    };

    // Same guard as `run_query`: a grant demanding a reason applies to every
    // way the caller reaches the target DB, plan-only included.
    if let Err(rejected) = ensure_reason(&target.constraints, args.reason.as_deref()) {
        return *rejected;
    }

    // The plan comes from Postgres' EXPLAIN; a Mongo or Redis target has no
    // SQL to parse, so it is answered before the parser can call it malformed.
    if matches!(target.server.kind, ServerKind::Mongo | ServerKind::Redis) {
        return error_outcome(
            OutcomeCode::UnsupportedBackend,
            "explain is not supported on this database's backend",
        );
    }

    // A data write may be planned only under a `query_write` grant.
    let writes_allowed = resolve_target(
        ctx,
        db_grants,
        Action::QueryWrite,
        &args.server,
        &args.database,
    )
    .is_some();
    let grant_access = if writes_allowed {
        Access::ReadWrite
    } else {
        Access::ReadOnly
    };
    let sql = match GuardedSql::parse(&args.sql, grant_access).await {
        Ok(sql) => sql,
        Err(err) => return guard_rejected(&err),
    };
    let access = sql.required_access();
    if args.analyze && access != Access::ReadOnly {
        return error_outcome(OutcomeCode::ForbiddenSql, ANALYZE_NEEDS_READ);
    }

    // The intent keeps the params too, so an `abandoned` row has them.
    let stored = (!args.params.is_empty()).then_some(args.params.as_slice());
    if let Err(refused) = record_intent(ctx, header, &target, access, stored).await {
        return *refused;
    }

    // Wall clock starts before pool open so error paths still carry
    // `duration_ms` into the audit row — spec 07 requires it on every call.
    let started = Instant::now();
    let adapter = match ctx
        .registry
        .get_or_open(target.server, target.database)
        .await
    {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };

    let query = ExplainQuery {
        sql,
        analyze: args.analyze,
        statement_timeout_ms: target.constraints.statement_timeout_ms,
        request_id: ctx.request.request_id,
    };
    let mut outcome = plan_outcome(
        id,
        adapter.explain_with_params(query, params).await,
        started,
    );
    if access == Access::ReadWrite {
        // Planned as the write role; plain EXPLAIN changes nothing.
        outcome.write = Some(WriteEffect {
            rows_affected: None,
            state: WriteState::NotApplied,
        });
    }
    outcome
}

fn plan_outcome(
    id: Value,
    explained: Result<crate::exec::ExecResult, crate::exec::ExecError>,
    started: Instant,
) -> Outcome {
    match explained {
        Ok(result) => {
            let elapsed = i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX);

            // Pull the plan out of result.rows[0][0]. Postgres returns it as
            // a JSON-formatted text value or already-parsed JSON.
            let plan = match extract_plan(&result) {
                Ok(p) => p,
                Err(()) => {
                    return error_outcome(
                        OutcomeCode::Internal,
                        "EXPLAIN returned an unexpected row shape",
                    );
                }
            };

            let payload = SuccessPayload {
                summary: summarize(&plan),
                plan,
                elapsed_ms: result.elapsed_ms,
            };
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => {
                    return error_outcome(OutcomeCode::Internal, "failed to serialize result");
                }
            };
            // EXPLAIN always returns one row (the plan); never truncated.
            success_outcome(id, text, Some(elapsed), Some(1), Some(false))
        }
        Err(err) => outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    }
}

/// Pull the JSON plan out of an `EXPLAIN (FORMAT JSON)` result.
///
/// Depending on Postgres version + sqlx decoding, the cell arrives as either
/// already-parsed JSON (array/object) or as a string containing the JSON
/// text. Handle both — anything else is an unexpected shape.
fn extract_plan(result: &crate::exec::ExecResult) -> Result<Value, ()> {
    let first_row = result.rows.first().ok_or(())?;
    let cell = first_row.first().ok_or(())?;
    match cell {
        Value::String(s) => serde_json::from_str(s).map_err(|_| ()),
        Value::Array(_) | Value::Object(_) => Ok(cell.clone()),
        _ => Err(()),
    }
}

#[path = "explain_summary.rs"]
mod summary;
use summary::{PlanSummary, summarize};

#[cfg(test)]
#[path = "explain_tests.rs"]
mod tests;
