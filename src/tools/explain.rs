//! `explain` — `EXPLAIN (FORMAT JSON)` wrapper. Returns the query plan
//! without executing the user's query.
//!
//! Same authz / audit / AST-guard path as `run_query`. The inner SQL is gated
//! through `sql_guard::ReadOnlySql::parse` before the adapter wraps it — so `EXPLAIN
//! DELETE FROM users` is rejected even though EXPLAIN without ANALYZE
//! doesn't execute (we stay conservative; an operator could enable ANALYZE
//! later thinking EXPLAIN is always safe).

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Action, Grant};
use crate::exec::ExplainQuery;
use crate::exec::sql_guard::{Access, ReadOnlySql};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, error_outcome, outcome_from_exec_error,
    reject_arguments, run_audited, success_outcome,
};
use super::target::{ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = "explain";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "EXPLAIN exceeded the configured statement_timeout",
    sql_rejected: "the target DB rejected the SQL",
    forbidden_prefix: "EXPLAIN",
};
#[derive(Debug, Deserialize)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub sql: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuccessPayload {
    /// The Postgres query plan as a JSON value (passed through verbatim from
    /// `EXPLAIN (FORMAT JSON)`'s single text column).
    plan: Value,
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
                "explain requires `server`, `database`, `sql` arguments",
            )
            .await;
        }
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

    let sql = match ReadOnlySql::parse(&args.sql) {
        Ok(sql) => sql,
        Err(err) => {
            return error_outcome(
                OutcomeCode::ForbiddenSql,
                &format!("SQL rejected by gateway: {err}"),
            );
        }
    };

    if let Err(refused) = record_intent(ctx, TOOL_NAME, &target, Access::ReadOnly).await {
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
        statement_timeout_ms: target.constraints.statement_timeout_ms,
    };
    match adapter.explain(query).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_plan_decodes_string_cell() {
        let result = crate::exec::ExecResult {
            columns: vec!["QUERY PLAN".to_string()],
            rows: vec![vec![Value::from(r#"[{"Plan":{"Node Type":"Seq Scan"}}]"#)]],
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        };
        let plan = extract_plan(&result).expect("decodes");
        assert_eq!(plan[0]["Plan"]["Node Type"], "Seq Scan");
    }

    #[test]
    fn extract_plan_passes_through_already_parsed_json() {
        // When sqlx decodes a `json` column directly, the cell is already a
        // Value::Array (or Object) — pass through without re-parsing.
        let result = crate::exec::ExecResult {
            columns: vec!["QUERY PLAN".to_string()],
            rows: vec![vec![serde_json::json!([{"Plan": {"Node Type": "Result"}}])]],
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        };
        let plan = extract_plan(&result).expect("passes through");
        assert_eq!(plan[0]["Plan"]["Node Type"], "Result");
    }

    #[test]
    fn extract_plan_errors_on_empty_or_unexpected_shape() {
        let empty = crate::exec::ExecResult {
            columns: vec![],
            rows: vec![],
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        };
        assert!(extract_plan(&empty).is_err());

        // Wrong cell type (number)
        let wrong = crate::exec::ExecResult {
            columns: vec!["QUERY PLAN".to_string()],
            rows: vec![vec![Value::from(42)]],
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        };
        assert!(extract_plan(&wrong).is_err());
    }
}
