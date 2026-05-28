//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit` + `truncated` flag).
//!
//! Per spec doc 03, errors are structured JSON with a `code` from the
//! published list (`forbidden`, `timeout`, `syntax_error`, `unavailable`,
//! `reason_required`, `internal`). We surface them as
//! `CallToolResult { is_error: true, content: [JSON-text] }` so the MCP
//! envelope stays a successful JSON-RPC response (per spec 03 §Errors).
//!
//! Audit (CLAUDE.md non-negotiable): every dispatch writes a row to
//! `audit_calls` before the response goes out. Audit write failure fails the
//! request — no best-effort audit.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::audit::{self, AuditRow};
use crate::auth::Identity;
use crate::authz::{self, Decision};
use crate::config::{Action, ConfigFile, Database, Server};
use crate::exec::{self, ExecError, PoolRegistry};
use crate::transport::jsonrpc::{ErrorObject, Response};
use crate::transport::protocol::{CallToolResult, TextContent};

const TOOL_NAME: &str = "run_query";

/// Hard floor on result rows when no grant constraint and no caller limit
/// apply. Spec 03 §"Results are size-capped" — keeps the gateway from holding
/// an unbounded result set in memory.
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

/// Same shape as a successful tool result, but carrying the outcome we'll
/// write to `audit_calls` after the work completes. Kept internal so the
/// audit hook stays the single chokepoint for every return.
struct Outcome {
    response: Response,
    /// One of `"success"` or a spec 03 error code. Audited verbatim.
    code: &'static str,
    elapsed_ms: Option<i64>,
}

pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    state_db: Option<&PgPool>,
    arguments: Option<Value>,
) -> Response {
    // Audit is non-negotiable: refuse to dispatch the tool without a state
    // DB to write into. Tests that exercise the wire protocol set
    // `state_db: None` and don't call `run_query`.
    let Some(state_db) = state_db else {
        return Response::error(
            id,
            ErrorObject::internal("audit log unavailable — refusing to dispatch run_query"),
        );
    };

    let args: Arguments = match arguments.map(serde_json::from_value::<Arguments>) {
        Some(Ok(a)) => a,
        _ => {
            return Response::error(
                id,
                ErrorObject::invalid_params(
                    "run_query requires `server`, `database`, `sql` arguments",
                ),
            );
        }
    };

    let outcome = compute_outcome(id.clone(), identity, config, registry, &args).await;

    // Synchronous audit write. Failure aborts the request — never let the
    // response go out without an audited row (CLAUDE.md non-negotiable).
    let row = AuditRow {
        request_id: id.to_string(),
        user_sub: identity.user_sub.clone(),
        user_email: identity.user_email.clone(),
        tool: TOOL_NAME.to_string(),
        server: Some(args.server.clone()),
        database: Some(args.database.clone()),
        sql: Some(args.sql.clone()),
        outcome: outcome.code.to_string(),
        elapsed_ms: outcome.elapsed_ms,
    };
    if let Err(err) = audit::log(state_db, &row).await {
        // Don't embed the underlying error string in the response (could
        // leak DB connection details on some sqlx error paths). Operator
        // sees the source via the tracing event.
        tracing::error!(%err, request_id = %id, "audit write failed; aborting tool response");
        return Response::error(
            id,
            ErrorObject::internal("audit write failed; request rejected"),
        );
    }

    outcome.response
}

async fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    args: &Arguments,
) -> Outcome {
    let Some((server, database)) = find_server_db(config, &args.server, &args.database) else {
        return Outcome {
            response: tool_error(id, "forbidden", "no grants for this server/database"),
            code: "forbidden",
            elapsed_ms: None,
        };
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
        Decision::Deny => {
            return Outcome {
                response: tool_error(id, "forbidden", "no grants for this server/database"),
                code: "forbidden",
                elapsed_ms: None,
            };
        }
    };

    if constraints.require_reason && args.reason.as_deref().is_none_or(str::is_empty) {
        return Outcome {
            response: tool_error(
                id,
                "reason_required",
                "policy requires a `reason` for this server/database",
            ),
            code: "reason_required",
            elapsed_ms: None,
        };
    }

    let row_limit = effective_row_limit(args.limit, constraints.row_limit);
    let timeout_ms = constraints.statement_timeout_ms;

    tracing::info!(
        request_id = %id,
        user = %identity.user_sub,
        server = %server.name,
        database = %database.name,
        row_limit,
        timeout_ms = ?timeout_ms,
        "tool.run_query.dispatch"
    );

    let pool = match registry.get_or_open(server, database).await {
        Ok(p) => p,
        Err(err) => return outcome_from_exec_error(id, err, None),
    };

    match exec::run_query(&pool, &args.sql, timeout_ms, row_limit).await {
        Ok(result) => {
            let elapsed = i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX);
            let payload = SuccessPayload {
                columns: &result.columns,
                rows: &result.rows,
                truncated: result.truncated,
                elapsed_ms: result.elapsed_ms,
            };
            // SuccessPayload only contains primitives + serde_json::Value
            // (which round-trips), so serialization is practically
            // infallible — but CLAUDE.md bans `expect` on the hot path, so
            // fall through to a typed internal error instead of panicking.
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => {
                    return Outcome {
                        response: tool_error(id, "internal", "failed to serialize result"),
                        code: "internal",
                        elapsed_ms: Some(elapsed),
                    };
                }
            };
            Outcome {
                response: Response::result(
                    id,
                    &CallToolResult {
                        content: vec![TextContent::new(text)],
                        is_error: false,
                    },
                ),
                code: "success",
                elapsed_ms: Some(elapsed),
            }
        }
        Err(err) => outcome_from_exec_error(id, err, None),
    }
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

fn effective_row_limit(caller: Option<u32>, grant: Option<u32>) -> u32 {
    let caller = caller.unwrap_or(DEFAULT_ROW_LIMIT);
    match grant {
        Some(grant_cap) => caller.min(grant_cap),
        None => caller,
    }
}

fn outcome_from_exec_error(id: Value, err: ExecError, elapsed_ms: Option<i64>) -> Outcome {
    let (code, message) = match err {
        ExecError::Timeout => ("timeout", "query exceeded the configured statement_timeout"),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", "the target DB rejected the SQL"),
        // Operator-facing config problem; user-side message stays generic.
        ExecError::PasswordUnresolved { .. } => ("internal", "server-side configuration error"),
    };
    Outcome {
        response: tool_error(id, code, message),
        code,
        elapsed_ms,
    }
}

fn tool_error(id: Value, code: &'static str, message: &str) -> Response {
    // Spec 03 §Errors: every error includes `request_id` so callers can
    // correlate with server logs. The JSON-RPC envelope already carries `id`,
    // but we duplicate it inside the structured body so the contract holds
    // when an agent only inspects the tool payload.
    let body = serde_json::json!({
        "request_id": id.clone(),
        "code": code,
        "message": message,
    });
    Response::result(
        id,
        &CallToolResult {
            content: vec![TextContent::new(body.to_string())],
            is_error: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_row_limit_takes_smaller() {
        assert_eq!(effective_row_limit(Some(10), Some(5)), 5);
        assert_eq!(effective_row_limit(Some(5), Some(10)), 5);
        assert_eq!(effective_row_limit(Some(50), None), 50);
        assert_eq!(effective_row_limit(None, Some(20)), 20);
        assert_eq!(effective_row_limit(None, None), DEFAULT_ROW_LIMIT);
    }

    #[test]
    fn tool_error_payload_shape() {
        let response = tool_error(Value::from(7), "forbidden", "nope");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["isError"], true);
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["message"], "nope");
        assert_eq!(body["request_id"], 7);
    }
}
