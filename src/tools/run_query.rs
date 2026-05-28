//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit + truncated` flag).
//!
//! Per spec doc 03, errors are structured JSON with a `code` from the
//! published list (`forbidden`, `timeout`, `syntax_error`, `unavailable`,
//! `reason_required`, `internal`). We surface them as
//! `CallToolResult { is_error: true, content: [JSON-text] }` so the MCP
//! envelope stays a successful JSON-RPC response (per spec 03 §Errors).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::Identity;
use crate::authz::{self, Decision};
use crate::config::{Action, ConfigFile, Database, Server};
use crate::exec::{self, ExecError, PoolRegistry};
use crate::transport::jsonrpc::{ErrorObject, Response};
use crate::transport::protocol::{CallToolResult, TextContent};

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

pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    arguments: Option<Value>,
) -> Response {
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

    // Look up server + db. Treat "not found" as forbidden so we never leak
    // whether a server exists to a caller with no grants on it (matches the
    // authz contract — absence-of-grant denies).
    let Some((server, database)) = find_server_db(config, &args.server, &args.database) else {
        return tool_error(id, "forbidden", "no grants for this server/database");
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
            return tool_error(id, "forbidden", "no grants for this server/database");
        }
    };

    if constraints.require_reason && args.reason.as_deref().is_none_or(str::is_empty) {
        return tool_error(
            id,
            "reason_required",
            "policy requires a `reason` for this server/database",
        );
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
        // Audit hook lands with #8 — this span carries the same fields so
        // we can wire the persister later without changing call sites.
        "tool.run_query.dispatch"
    );

    let pool = match registry.get_or_open(server, database).await {
        Ok(p) => p,
        Err(err) => return tool_error_from_exec(id, err),
    };

    match exec::run_query(&pool, &args.sql, timeout_ms, row_limit).await {
        Ok(result) => {
            let payload = SuccessPayload {
                columns: &result.columns,
                rows: &result.rows,
                truncated: result.truncated,
                elapsed_ms: result.elapsed_ms,
            };
            // SuccessPayload only contains primitives + serde_json::Value
            // (which round-trips), so serialization is practically
            // infallible — but CLAUDE.md bans `expect` on the hot path, so we
            // fall through to a typed internal error instead of panicking.
            let text = match serde_json::to_string(&payload) {
                Ok(t) => t,
                Err(_) => return tool_error(id, "internal", "failed to serialize result"),
            };
            Response::result(
                id,
                &CallToolResult {
                    content: vec![TextContent::new(text)],
                    is_error: false,
                },
            )
        }
        Err(err) => tool_error_from_exec(id, err),
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

fn tool_error_from_exec(id: Value, err: ExecError) -> Response {
    let (code, message) = match err {
        ExecError::Timeout => ("timeout", "query exceeded the configured statement_timeout"),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", "the target DB rejected the SQL"),
        // Operator-facing config problem; user-side message stays generic.
        ExecError::PasswordUnresolved { .. } => ("internal", "server-side configuration error"),
    };
    tool_error(id, code, message)
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
        let response = tool_error(serde_json::Value::from(7), "forbidden", "nope");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["isError"], true);
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["request_id"], 7);
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["message"], "nope");
    }
}
