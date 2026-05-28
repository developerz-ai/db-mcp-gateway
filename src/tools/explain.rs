//! `explain` — `EXPLAIN (FORMAT JSON)` wrapper. Returns the query plan
//! without executing the user's query.
//!
//! Same authz / audit / AST-guard path as `run_query`. The inner SQL is gated
//! through `exec::sql_guard::is_read_only` before we wrap it — so `EXPLAIN
//! DELETE FROM users` is rejected even though EXPLAIN without ANALYZE
//! doesn't execute (we stay conservative; an operator could enable ANALYZE
//! later thinking EXPLAIN is always safe).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, Decision};
use crate::config::{Action, ConfigFile, Database, Server};
use crate::exec::sql_guard;
use crate::exec::{self, ExecError, PoolRegistry};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, error_outcome, success_outcome,
};

const TOOL_NAME: &str = "explain";
/// EXPLAIN always returns a tiny result (one row, one column containing the
/// plan JSON). A row cap exists only as a sanity bound — should never trip.
const EXPLAIN_RESULT_CAP: u32 = 100;

#[derive(Debug, Deserialize)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub sql: String,
}

#[derive(Debug, Serialize)]
struct SuccessPayload {
    /// The Postgres query plan as a JSON value (passed through verbatim from
    /// `EXPLAIN (FORMAT JSON)`'s single text column).
    plan: Value,
    elapsed_ms: u64,
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
                ErrorObject::invalid_params(
                    "explain requires `server`, `database`, `sql` arguments",
                ),
            );
        }
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        // Audit the *user's* SQL, not the EXPLAIN-wrapped one — operators
        // see what the agent asked for.
        sql: Some(&args.sql),
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
        Action::QueryRead,
        &server.name,
        &database.name,
        &config.permissions,
    );
    let constraints = match decision {
        Decision::Allow { constraints } => constraints,
        Decision::Deny => return forbidden(id),
    };

    if let Err(err) = sql_guard::is_read_only(&args.sql) {
        return error_outcome(
            id,
            "forbidden_sql",
            &format!("SQL rejected by gateway: {err}"),
        );
    }

    // Wrap *after* the guard accepts — the inner SQL is now known read-only.
    // EXPLAIN (FORMAT JSON) returns one row, one column ("QUERY PLAN"),
    // containing the plan as a JSON-formatted string.
    let sql = format!("EXPLAIN (FORMAT JSON) {}", args.sql);
    let timeout_ms = constraints.statement_timeout_ms;

    let pool = match registry.get_or_open(server, database).await {
        Ok(p) => p,
        Err(err) => return outcome_from_exec_error(id, err),
    };

    match exec::run_query(&pool, &sql, timeout_ms, EXPLAIN_RESULT_CAP).await {
        Ok(result) => {
            let elapsed = i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX);

            // Pull the plan out of result.rows[0][0]. Postgres returns it as
            // a JSON-formatted text value or already-parsed JSON.
            let plan = match extract_plan(&result) {
                Ok(p) => p,
                Err(()) => {
                    return error_outcome(
                        id,
                        "internal",
                        "EXPLAIN returned an unexpected row shape",
                    );
                }
            };

            let payload = SuccessPayload {
                plan,
                elapsed_ms: result.elapsed_ms,
            };
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => return error_outcome(id, "internal", "failed to serialize result"),
            };
            // EXPLAIN always returns one row (the plan); never truncated.
            success_outcome(id, text, Some(elapsed), Some(1), Some(false))
        }
        Err(err) => outcome_from_exec_error(id, err),
    }
}

/// Pull the JSON plan out of an `EXPLAIN (FORMAT JSON)` result.
///
/// Depending on Postgres version + sqlx decoding, the cell arrives as either
/// already-parsed JSON (array/object) or as a string containing the JSON
/// text. Handle both — anything else is an unexpected shape.
fn extract_plan(result: &exec::ExecResult) -> Result<Value, ()> {
    let first_row = result.rows.first().ok_or(())?;
    let cell = first_row.first().ok_or(())?;
    match cell {
        Value::String(s) => serde_json::from_str(s).map_err(|_| ()),
        Value::Array(_) | Value::Object(_) => Ok(cell.clone()),
        _ => Err(()),
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

fn outcome_from_exec_error(id: Value, err: ExecError) -> Outcome {
    let (code, message) = match err {
        ExecError::Timeout => (
            "timeout",
            "EXPLAIN exceeded the configured statement_timeout",
        ),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", "the target DB rejected the SQL"),
        ExecError::PasswordUnresolved { .. } => ("internal", "server-side configuration error"),
    };
    error_outcome(id, code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_plan_decodes_string_cell() {
        let result = exec::ExecResult {
            columns: vec!["QUERY PLAN".to_string()],
            rows: vec![vec![Value::from(r#"[{"Plan":{"Node Type":"Seq Scan"}}]"#)]],
            truncated: false,
            elapsed_ms: 0,
        };
        let plan = extract_plan(&result).expect("decodes");
        assert_eq!(plan[0]["Plan"]["Node Type"], "Seq Scan");
    }

    #[test]
    fn extract_plan_passes_through_already_parsed_json() {
        // When sqlx decodes a `json` column directly, the cell is already a
        // Value::Array (or Object) — pass through without re-parsing.
        let result = exec::ExecResult {
            columns: vec!["QUERY PLAN".to_string()],
            rows: vec![vec![serde_json::json!([{"Plan": {"Node Type": "Result"}}])]],
            truncated: false,
            elapsed_ms: 0,
        };
        let plan = extract_plan(&result).expect("passes through");
        assert_eq!(plan[0]["Plan"]["Node Type"], "Result");
    }

    #[test]
    fn extract_plan_errors_on_empty_or_unexpected_shape() {
        let empty = exec::ExecResult {
            columns: vec![],
            rows: vec![],
            truncated: false,
            elapsed_ms: 0,
        };
        assert!(extract_plan(&empty).is_err());

        // Wrong cell type (number)
        let wrong = exec::ExecResult {
            columns: vec!["QUERY PLAN".to_string()],
            rows: vec![vec![Value::from(42)]],
            truncated: false,
            elapsed_ms: 0,
        };
        assert!(extract_plan(&wrong).is_err());
    }
}
