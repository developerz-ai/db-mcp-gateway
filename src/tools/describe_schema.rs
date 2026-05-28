//! `describe_schema` — tables + columns + types for a database's schema.
//!
//! Action: `SchemaRead`. Reads from `information_schema.columns` via the
//! per-DB pool. Schema/table args are passed as bound parameters (not
//! interpolated), so no identifier-injection risk.
//!
//! Per the issue body, the response shape is tables + columns + types only;
//! PK/FK/indexes (mentioned in spec doc 03 §describe_schema) are deferred to
//! a follow-up.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, Decision};
use crate::config::{Action, ConfigFile, Database, Server};
use crate::exec::{self, ExecError, PoolRegistry};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, error_outcome, success_outcome,
};

const TOOL_NAME: &str = "describe_schema";
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

pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    arguments: Option<Value>,
) -> Response {
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
    };
    let work = compute_outcome(id.clone(), identity, config, registry, &args);
    audit_dispatch(id, identity, state_db, request_ctx, header, work).await
}

async fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    args: &Arguments,
) -> Outcome {
    let Some((server, database)) = find_server_db(config, &args.server, &args.database) else {
        return forbidden(id);
    };

    let decision = authz::evaluate(
        identity,
        Action::SchemaRead,
        &server.name,
        &database.name,
        &config.permissions,
    );
    let constraints = match decision {
        Decision::Allow { constraints } => constraints,
        Decision::Deny => return forbidden(id),
    };

    let schema = args.schema.as_deref().unwrap_or(DEFAULT_SCHEMA);
    let (sql, binds) = build_catalog_query(schema, args.table.as_deref());

    let pool = match registry.get_or_open(server, database).await {
        Ok(p) => p,
        Err(err) => return outcome_from_exec_error(id, err),
    };

    let result = exec::run_query_with_string_binds(
        &pool,
        &sql,
        &binds,
        constraints.statement_timeout_ms,
        MAX_CATALOG_ROWS,
    )
    .await;

    match result {
        Ok(exec_result) => {
            let elapsed = i64::try_from(exec_result.elapsed_ms).unwrap_or(i64::MAX);
            let payload = match assemble_tables(&exec_result) {
                Ok(p) => p,
                Err(_) => {
                    return error_outcome(
                        id,
                        "internal",
                        "catalog response shape changed unexpectedly",
                    );
                }
            };
            let table_count = i64::try_from(payload.tables.len()).unwrap_or(i64::MAX);
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => return error_outcome(id, "internal", "failed to serialize result"),
            };
            // row_count = number of tables surfaced; describe_schema doesn't
            // truncate, so always Some(false) — operators can tell from the
            // audit row whether the call produced data.
            success_outcome(id, text, Some(elapsed), Some(table_count), Some(false))
        }
        Err(err) => outcome_from_exec_error(id, err),
    }
}

fn forbidden(id: Value) -> Outcome {
    error_outcome(id, "forbidden", "no grants for this server/database")
}

fn find_server_db<'a>(
    config: &'a ConfigFile,
    server_name: &str,
    database_name: &str,
) -> Option<(&'a Server, &'a Database)> {
    let server = config.servers.iter().find(|s| s.name == server_name)?;
    let database = server.databases.iter().find(|d| d.name == database_name)?;
    Some((server, database))
}

/// Build the catalog query + the bind values that go with it. Schema and
/// table go through `$1` / `$2` — they're values, not identifiers, in this
/// query, so the standard parameterised path is safe.
fn build_catalog_query<'a>(schema: &'a str, table: Option<&'a str>) -> (String, Vec<&'a str>) {
    let base = "SELECT table_schema, table_name, column_name, data_type, is_nullable \
                FROM information_schema.columns \
                WHERE table_schema = $1";
    let order = " ORDER BY table_name, ordinal_position";
    if let Some(_table) = table {
        let sql = format!("{base} AND table_name = $2{order}");
        (sql, vec![schema, table.unwrap_or("")])
    } else {
        let sql = format!("{base}{order}");
        (sql, vec![schema])
    }
}

/// Group `information_schema.columns` rows by `(schema, table_name)` into the
/// nested `tables` shape clients want.
fn assemble_tables(result: &exec::ExecResult) -> Result<DescribeSchemaResult, ()> {
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

fn outcome_from_exec_error(id: Value, err: ExecError) -> Outcome {
    let (code, message) = match err {
        ExecError::Timeout => ("timeout", "catalog query exceeded statement_timeout"),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", "catalog query was rejected"),
        ExecError::PasswordUnresolved { .. } => ("internal", "server-side configuration error"),
    };
    error_outcome(id, code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_query_uses_bind_params() {
        let (sql, binds) = build_catalog_query("public", None);
        assert!(sql.contains("table_schema = $1"), "{sql}");
        assert!(!sql.contains("AND table_name"), "{sql}");
        assert_eq!(binds, vec!["public"]);

        let (sql, binds) = build_catalog_query("acme", Some("users"));
        assert!(sql.contains("table_schema = $1"));
        assert!(sql.contains("AND table_name = $2"));
        assert_eq!(binds, vec!["acme", "users"]);
    }

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
        let exec_result = exec::ExecResult {
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
