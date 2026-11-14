//! `sample_table` — the first `n` rows of one table, under the caller's
//! grant row cap.
//!
//! Schema and table are caller input that the adapter interpolates as
//! identifiers, so both must parse as [`Identifier`] here; anything else is
//! rejected before the adapter sees it.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Action, Grant};
use crate::exec::mongo::sample_command;
use crate::exec::sql_guard::Access;
use crate::exec::{IDENTIFIER_PATTERN, Identifier, SampleQuery};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, audit_outcome, error_outcome,
    invalid_arguments, outcome_from_exec_error, reject_arguments, run_audited, success_outcome,
};
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
}

#[derive(Debug, Serialize)]
struct SuccessPayload<'a> {
    columns: &'a [String],
    rows: &'a [Vec<Value>],
    truncated: bool,
    elapsed_ms: u64,
}

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
    // Validated at the edge: the adapter interpolates both as identifiers,
    // and the audit row names the table they make up.
    let table = match parse_table(args.schema.as_deref(), &args.table) {
        Ok(table) => table,
        Err(field) => {
            let outcome = invalid_arguments(
                id.clone(),
                &format!("`{field}` must match {IDENTIFIER_PATTERN}"),
            );
            return audit_outcome(ctx, id, header, outcome).await;
        }
    };
    let read = audited_read(header.db_type, table);
    header.sql = Some(&read);
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args, table).await
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

/// `Err` names the argument that is not an identifier.
fn parse_table<'a>(schema: Option<&'a str>, table: &'a str) -> Result<TableRef<'a>, &'static str> {
    let schema = Identifier::parse(schema.unwrap_or(DEFAULT_SCHEMA)).map_err(|_| "schema")?;
    let table = Identifier::parse(table).map_err(|_| "table")?;
    Ok(TableRef { schema, table })
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
    table: TableRef<'_>,
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
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };

    let query = SampleQuery {
        schema: table.schema,
        table: table.table,
        statement_timeout_ms: constraints.statement_timeout_ms,
        row_limit,
        request_id: ctx.request.request_id,
    };
    match adapter.sample(query).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_table_defaults_schema_and_names_the_bad_argument() {
        let table = parse_table(None, "users").expect("valid");
        assert_eq!(table.schema.as_str(), DEFAULT_SCHEMA);
        assert_eq!(table.table.as_str(), "users");
        assert_eq!(
            parse_table(Some("bad-schema"), "users").err(),
            Some("schema")
        );
        assert_eq!(parse_table(None, "users; drop").err(), Some("table"));
    }

    #[test]
    fn audited_read_names_the_table_or_the_mongo_find() {
        let table = parse_table(Some("sales"), "orders").expect("valid");
        assert_eq!(audited_read(Some("postgres"), table), "sales.orders");
        let find: Value = serde_json::from_str(&audited_read(Some("mongo"), table))
            .expect("the Mongo read is a JSON command");
        assert_eq!(find, serde_json::json!({ "find": "orders", "filter": {} }));
    }
}
