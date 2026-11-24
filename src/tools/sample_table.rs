//! `sample_table` — the first `n` rows of one table, under the caller's
//! grant row cap.
//!
//! Schema and table are caller input that the adapter interpolates as
//! identifiers, so both must parse as [`Identifier`] here; anything else is
//! rejected before the adapter sees it.

use std::num::NonZeroU32;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Action, Grant};
use crate::exec::mongo::sample_command;
use crate::exec::sql_guard::Access;
use crate::exec::{
    COLLECTION_PATTERN, ExecError, ExecResult, IDENTIFIER_PATTERN, Identifier, SampleQuery,
};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::{LIMIT_AT_LEAST_ONE, parse_arguments};
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, audit_outcome, elapsed_ms_since,
    error_outcome, invalid_arguments, note_timeout_limit, outcome_from_exec_error,
    reject_arguments, run_audited,
};
use super::tabular::caps::{ByteCaps, RowLimit};
use super::tabular::columns::project;
use super::tabular::{RowShaping, rows_outcome};
use super::target::{effective_row_limit, ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = "sample_table";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "query exceeded the configured statement_timeout",
    sql_rejected: "the target DB rejected the SQL",
    forbidden_prefix: "sample",
};
const DEFAULT_SCHEMA: &str = "public";
/// Hard floor on rows sampled when no grant constraint and no caller limit
/// apply. `sample_table` exists for "peek at the shape of the data" — small
/// by default, never giant.
const DEFAULT_SAMPLE_LIMIT: u32 = 10;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub table: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Return only these columns (on Mongo: these top-level fields).
    #[serde(default)]
    pub columns: Option<Vec<String>>,
    /// Cap on the JSON size of the returned rows (spec 03 §Results).
    #[serde(default)]
    pub max_bytes: Option<NonZeroU32>,
    /// Cap on one cell's JSON size; a larger cell becomes a marker.
    #[serde(default)]
    pub max_cell_bytes: Option<NonZeroU32>,
}

/// `sample_table` has no fields beyond the shared row-result ones.
#[derive(Debug, Serialize)]
struct NoExtraFields {}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };

    let mut header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: None,
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };
    if args.limit == Some(0) {
        let outcome = invalid_arguments(id.clone(), LIMIT_AT_LEAST_ONE);
        return audit_outcome(ctx, id, header, outcome).await;
    }
    // Validated at the edge: the adapter interpolates both as identifiers,
    // and the audit row names the table they make up.
    let table = match parse_table(header.db_type, args.schema.as_deref(), &args.table) {
        Ok(table) => table,
        Err((field, pattern)) => {
            let outcome = invalid_arguments(id.clone(), &format!("`{field}` must match {pattern}"));
            return audit_outcome(ctx, id, header, outcome).await;
        }
    };
    let columns = match parse_columns(args.columns.as_deref()) {
        Ok(columns) => columns,
        Err(message) => {
            let outcome = invalid_arguments(id.clone(), &message);
            return audit_outcome(ctx, id, header, outcome).await;
        }
    };
    let read = audited_read(header.db_type, table);
    header.sql = Some(&read);
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args, table, &columns).await
    })
    .await
}

/// The `(schema, table)` a sample reads, both validated identifiers.
#[derive(Debug, Clone, Copy)]
struct TableRef<'a> {
    schema: Identifier<'a>,
    table: Identifier<'a>,
}

/// What the audit row's `sql` says was read: `schema.table`, or on Mongo,
/// which has no schemas, the `find` command the adapter runs.
fn audited_read(db_type: Option<&str>, table: TableRef<'_>) -> String {
    match db_type {
        Some("mongo") => sample_command(table.table),
        _ => format!("{}.{}", table.schema.as_str(), table.table.as_str()),
    }
}

/// The `columns` to keep, if named: at least one, each an identifier, none
/// twice. `Err` is the client message.
fn parse_columns(columns: Option<&[String]>) -> Result<Vec<&str>, String> {
    let Some(columns) = columns else {
        return Ok(Vec::new());
    };
    if columns.is_empty() {
        return Err("`columns` must name at least one column".to_owned());
    }
    let mut names: Vec<&str> = Vec::with_capacity(columns.len());
    for column in columns {
        let name = Identifier::parse(column)
            .map_err(|_| format!("every `columns` entry must match {IDENTIFIER_PATTERN}"))?
            .as_str();
        if names.contains(&name) {
            return Err(format!("`columns` names `{name}` twice"));
        }
        names.push(name);
    }
    Ok(names)
}

/// `Err` names the argument that is not an identifier and the rule it
/// broke: on Mongo, `table` is a collection name ([`COLLECTION_PATTERN`]).
fn parse_table<'a>(
    db_type: Option<&str>,
    schema: Option<&'a str>,
    table: &'a str,
) -> Result<TableRef<'a>, (&'static str, &'static str)> {
    let schema = Identifier::parse(schema.unwrap_or(DEFAULT_SCHEMA))
        .map_err(|_| ("schema", IDENTIFIER_PATTERN))?;
    let table = match db_type {
        Some("mongo") => {
            Identifier::parse_collection(table).map_err(|_| ("table", COLLECTION_PATTERN))
        }
        _ => Identifier::parse(table).map_err(|_| ("table", IDENTIFIER_PATTERN)),
    }?;
    Ok(TableRef { schema, table })
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
    table: TableRef<'_>,
    columns: &[&str],
) -> Outcome {
    // `query_read`, not `schema_read`: this tool returns *row data*. A
    // `schema_read` grant is metadata-only, and `Action::includes` would let a
    // bare `schema_read` satisfy a `SchemaRead` request — so gating on
    // `SchemaRead` here would hand table contents to a metadata-only grant.
    // Same action `run_query` and `explain` use.
    let Some(target) = resolve_target(
        ctx,
        db_grants,
        Action::QueryRead,
        &args.server,
        &args.database,
    ) else {
        return forbidden();
    };
    let constraints = &target.constraints;

    // Same guard as `run_query`: this tool returns rows, so a grant demanding
    // a reason must not be satisfiable by sampling instead of querying.
    if let Err(rejected) = ensure_reason(constraints, args.reason.as_deref()) {
        return *rejected;
    }
    let row_limit = effective_row_limit(args.limit, constraints.row_limit, DEFAULT_SAMPLE_LIMIT);

    if let Err(refused) = record_intent(ctx, header, &target, Access::ReadOnly).await {
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
        Err(err) => return exec_failed(err, started, constraints.statement_timeout_ms),
    };

    let query = SampleQuery {
        schema: table.schema,
        table: table.table,
        statement_timeout_ms: constraints.statement_timeout_ms,
        row_limit,
        request_id: ctx.request.request_id,
    };
    let shaping = RowShaping {
        limit: RowLimit {
            effective: row_limit,
            asked: args.limit.unwrap_or(DEFAULT_SAMPLE_LIMIT),
        },
        caps: ByteCaps {
            max_bytes: args.max_bytes,
            max_cell_bytes: args.max_cell_bytes,
        },
        kind: target.server.kind,
    };
    match adapter.sample(query).await {
        Ok(result) => sampled_outcome(id, result, shaping, columns, started),
        Err(err) => exec_failed(err, started, constraints.statement_timeout_ms),
    }
}

fn exec_failed(err: ExecError, started: Instant, grant_timeout_ms: Option<u32>) -> Outcome {
    let mut outcome = outcome_from_exec_error(err, started, &ERROR_MESSAGES);
    note_timeout_limit(&mut outcome, grant_timeout_ms);
    outcome
}

/// Keep the named `columns` (all when none were named), then size the rows.
/// A named column the table lacks is `undefined_object`, as Postgres
/// answers the same name in a `SELECT` list.
fn sampled_outcome(
    id: Value,
    mut result: ExecResult,
    shaping: RowShaping,
    columns: &[&str],
    started: Instant,
) -> Outcome {
    if !columns.is_empty()
        && let Err(missing) = project(shaping.kind, &mut result, columns)
    {
        let message = format!(
            "column does not exist: {}; describe_schema lists the table's columns",
            missing.join(", ")
        );
        let mut outcome = error_outcome(OutcomeCode::UndefinedObject, &message);
        outcome.elapsed_ms = Some(elapsed_ms_since(started));
        return outcome;
    }
    rows_outcome(id, result, shaping, NoExtraFields {})
}

#[cfg(test)]
#[path = "sample_table_tests.rs"]
mod tests;
