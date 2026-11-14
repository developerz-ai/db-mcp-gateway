//! `table_stats` — size, row estimate, dead tuples, last vacuum/analyze and
//! per-index size + scan counts for a schema or one table.
//!
//! Action: `SchemaRead` — statistics are metadata, never row data. The adapter
//! reads the statistics views under the read role, inside a read-only
//! transaction and the statement timeout; schema/table are bound values.

use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::config::{Action, Grant};
use crate::exec::{Access, TableStatsQuery};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, ToolErrorMessages, outcome_from_exec_error, reject_arguments, run_audited,
};
use super::tabular::tabular_outcome;
use super::target::{ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = super::TABLE_STATS;
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "statistics query exceeded statement_timeout",
    sql_rejected: "statistics query was rejected",
    forbidden_prefix: "statistics query",
};
const DEFAULT_SCHEMA: &str = "public";
/// One row per table; a schema with more tables than this is reported
/// `truncated`.
const MAX_STATS_ROWS: u32 = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };

    let schema = args.schema.as_deref().unwrap_or(DEFAULT_SCHEMA);
    let read = match args.table.as_deref() {
        Some(table) => format!("{schema}.{table}"),
        None => schema.to_owned(),
    };
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: Some(&read),
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args, schema).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
    schema: &str,
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
    if let Err(refused) = record_intent(ctx, header, &target, Access::ReadOnly).await {
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
    let query = TableStatsQuery {
        schema,
        table: args.table.as_deref(),
        statement_timeout_ms: target.constraints.statement_timeout_ms,
        row_limit: MAX_STATS_ROWS,
        request_id: ctx.request.request_id,
    };
    match adapter.table_stats(query).await {
        Ok(result) => tabular_outcome(id, &result, &result.rows),
        Err(err) => outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    }
}
