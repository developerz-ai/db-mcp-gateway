//! `describe_schema` — tables + columns + types for a database's schema.
//!
//! Action: `SchemaRead`. The adapter runs the catalog lookup; schema/table
//! reach it as bound values, never interpolated identifiers.
//!
//! Per the issue body, the response shape is tables + columns + types only;
//! PK/FK/indexes (mentioned in spec doc 03 §describe_schema) are deferred to
//! a follow-up.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Action, Grant};
use crate::exec::{ExecResult, SchemaQuery};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, error_outcome, outcome_from_exec_error,
    run_audited, success_outcome,
};
use super::target::{forbidden, resolve_target};

const TOOL_NAME: &str = "describe_schema";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "catalog query exceeded statement_timeout",
    sql_rejected: "catalog query was rejected",
    forbidden_prefix: "catalog query",
};
const DEFAULT_SCHEMA: &str = "public";
/// One Postgres database can hold tens of thousands of columns across all
/// schemas. Cap the catalog query so a degenerate request can't dominate the
/// pool. Per-grant `row_limit` is *not* applied here — that constraint is
/// about user data, not catalog metadata.
const MAX_CATALOG_ROWS: u32 = 50_000;

#[derive(Debug, Deserialize)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
}

#[derive(Debug, Serialize)]
struct ColumnView {
    name: String,
    data_type: String,
    nullable: bool,
}

#[derive(Debug, Serialize)]
struct TableView {
    schema: String,
    name: String,
    columns: Vec<ColumnView>,
}

#[derive(Debug, Serialize)]
struct DescribeSchemaResult {
    tables: Vec<TableView>,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match arguments.map(serde_json::from_value::<Arguments>) {
        Some(Ok(a)) => a,
        _ => {
            return Response::error(
                id,
                ErrorObject::invalid_params("describe_schema requires `server` and `database`"),
            );
        }
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: None,
        reason: None,
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
        return forbidden(id);
    };

    // Wall clock starts before pool open so error paths still carry
    // `duration_ms` into the audit row — spec 07 requires it on every call.
    let started = Instant::now();
    let adapter = match ctx
        .registry
        .get_or_open(target.server, target.database)
        .await
    {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(id, err, started, &ERROR_MESSAGES),
    };

    let query = SchemaQuery {
        schema: args.schema.as_deref().unwrap_or(DEFAULT_SCHEMA),
        table: args.table.as_deref(),
        statement_timeout_ms: target.constraints.statement_timeout_ms,
        row_limit: MAX_CATALOG_ROWS,
    };
    let result = adapter.describe_schema(query).await;

    match result {
        Ok(exec_result) => {
            let elapsed = i64::try_from(exec_result.elapsed_ms).unwrap_or(i64::MAX);
            let payload = match assemble_tables(&exec_result) {
                Ok(p) => p,
                Err(_) => {
                    return error_outcome(
                        id,
                        OutcomeCode::Internal,
                        "catalog response shape changed unexpectedly",
                    );
                }
            };
            let table_count = i64::try_from(payload.tables.len()).unwrap_or(i64::MAX);
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => {
                    return error_outcome(id, OutcomeCode::Internal, "failed to serialize result");
                }
            };
            // row_count = number of tables surfaced. The catalog scan IS
            // capped (`MAX_CATALOG_ROWS`), so persist the real truncation
            // flag from exec — otherwise operators can't tell a clipped
            // schema from a complete one.
            success_outcome(
                id,
                text,
                Some(elapsed),
                Some(table_count),
                Some(exec_result.truncated),
            )
        }
        Err(err) => outcome_from_exec_error(id, err, started, &ERROR_MESSAGES),
    }
}

/// Group `information_schema.columns` rows by `(schema, table_name)` into the
/// nested `tables` shape clients want.
fn assemble_tables(result: &ExecResult) -> Result<DescribeSchemaResult, ()> {
    let mut tables: Vec<TableView> = Vec::new();
    for row in &result.rows {
        // Expected columns by index:
        //   0 table_schema, 1 table_name, 2 column_name, 3 data_type, 4 is_nullable
        if row.len() < 5 {
            return Err(());
        }
        let schema = row[0].as_str().ok_or(())?.to_string();
        let table = row[1].as_str().ok_or(())?.to_string();
        let column_name = row[2].as_str().ok_or(())?.to_string();
        let data_type = row[3].as_str().ok_or(())?.to_string();
        // `is_nullable` from information_schema is the text "YES"/"NO".
        let nullable = row[4].as_str().map(|s| s == "YES").unwrap_or(false);

        let column = ColumnView {
            name: column_name,
            data_type,
            nullable,
        };
        match tables.last_mut() {
            Some(t) if t.schema == schema && t.name == table => {
                t.columns.push(column);
            }
            _ => tables.push(TableView {
                schema,
                name: table,
                columns: vec![column],
            }),
        }
    }
    Ok(DescribeSchemaResult { tables })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms `assemble_tables` correctly groups consecutive rows by
    /// (schema, table_name) and decodes is_nullable from the YES/NO text
    /// that information_schema returns.
    #[test]
    fn assemble_groups_by_table_and_decodes_nullable() {
        let rows = vec![
            vec![
                Value::from("public"),
                Value::from("users"),
                Value::from("id"),
                Value::from("bigint"),
                Value::from("NO"),
            ],
            vec![
                Value::from("public"),
                Value::from("users"),
                Value::from("email"),
                Value::from("text"),
                Value::from("YES"),
            ],
            vec![
                Value::from("public"),
                Value::from("orders"),
                Value::from("id"),
                Value::from("bigint"),
                Value::from("NO"),
            ],
        ];
        let exec_result = ExecResult {
            columns: vec![
                "table_schema".into(),
                "table_name".into(),
                "column_name".into(),
                "data_type".into(),
                "is_nullable".into(),
            ],
            rows,
            truncated: false,
            elapsed_ms: 0,
        };
        let assembled = assemble_tables(&exec_result).unwrap();
        assert_eq!(assembled.tables.len(), 2);
        assert_eq!(assembled.tables[0].name, "users");
        assert_eq!(assembled.tables[0].columns.len(), 2);
        assert!(!assembled.tables[0].columns[0].nullable);
        assert!(assembled.tables[0].columns[1].nullable);
        assert_eq!(assembled.tables[1].name, "orders");
        assert_eq!(assembled.tables[1].columns.len(), 1);
    }
}
