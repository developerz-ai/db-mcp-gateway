//! `db_activity` — what the gateway is running on one database right now:
//! pid, state, wait event and duration of each backend, keyed by the gateway
//! `request_id` that backend runs for.
//!
//! Action: `SchemaRead`. The adapter lists only the gateway's own roles'
//! backends; this tool then keeps only the caller's OWN requests (those whose
//! intent row carries the caller's identity), so one identity never sees
//! another's activity. No query text: the caller's statements are in its
//! audit rows and `get_query_history`.

use std::collections::HashSet;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::config::{Action, Grant};
use crate::exec::{Access, ActivityQuery, ExecResult};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, error_outcome, outcome_from_exec_error,
    reject_arguments, run_audited,
};
use super::tabular::tabular_outcome;
use super::target::{Target, ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = super::DB_ACTIVITY;
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "activity query exceeded statement_timeout",
    sql_rejected: "activity query was rejected",
    forbidden_prefix: "activity query",
};
/// Backends listed before the ownership filter; a pool never holds more.
const MAX_ACTIVITY_ROWS: u32 = 1_000;
const REQUEST_ID_COLUMN: &str = "request_id";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let Some(Ok(args)) = arguments.map(serde_json::from_value::<Arguments>) else {
        return reject_arguments(
            ctx,
            id,
            TOOL_NAME,
            "db_activity requires `server` and `database` arguments",
        )
        .await;
    };
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: None,
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
    let Some(target) = resolve_target(
        ctx,
        db_grants,
        Action::SchemaRead,
        &args.server,
        &args.database,
    ) else {
        return forbidden();
    };
    if let Err(rejected) = ensure_reason(&target.constraints, args.reason.as_deref()) {
        return *rejected;
    }
    if let Err(refused) = record_intent(ctx, TOOL_NAME, &target, Access::ReadOnly).await {
        return *refused;
    }

    let started = Instant::now();
    let adapter = match ctx
        .registry
        .get_or_open(target.server, target.database)
        .await
    {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };
    let query = ActivityQuery {
        statement_timeout_ms: target.constraints.statement_timeout_ms,
        row_limit: MAX_ACTIVITY_ROWS,
        request_id: ctx.request.request_id,
    };
    let result = match adapter.db_activity(query).await {
        Ok(result) => result,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };
    match own_rows(ctx, &target, &result).await {
        Ok(rows) => tabular_outcome(id, &result, &rows),
        Err(outcome) => *outcome,
    }
}

/// The rows of `result` whose `request_id` is one of the caller's own.
async fn own_rows(
    ctx: ToolCtx<'_>,
    target: &Target<'_>,
    result: &ExecResult,
) -> Result<Vec<Vec<Value>>, Box<Outcome>> {
    let Some(column) = result.columns.iter().position(|c| c == REQUEST_ID_COLUMN) else {
        return Err(Box::new(error_outcome(
            OutcomeCode::Internal,
            "activity response shape changed unexpectedly",
        )));
    };
    let tagged: Vec<String> = result
        .rows
        .iter()
        .filter_map(|row| row.get(column)?.as_str().map(str::to_owned))
        .collect();
    let owned = crate::state::audit::select_owned_request_ids(
        ctx.state_db,
        &ctx.identity.user_sub,
        &target.server.name,
        &target.database.name,
        &tagged,
    )
    .await
    .map_err(|err| {
        tracing::error!(
            class = %crate::state::connect_error_class(&err),
            "activity ownership lookup failed"
        );
        Box::new(error_outcome(
            OutcomeCode::Internal,
            "activity ownership lookup failed",
        ))
    })?;
    let owned: HashSet<String> = owned.into_iter().collect();
    Ok(result
        .rows
        .iter()
        .filter(|row| {
            row.get(column)
                .and_then(Value::as_str)
                .is_some_and(|id| owned.contains(id))
        })
        .cloned()
        .collect())
}
