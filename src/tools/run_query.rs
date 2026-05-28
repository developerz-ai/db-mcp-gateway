//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit` + `truncated` flag).
//!
//! Per spec doc 03, errors are structured JSON with a `code` from the
//! published list (`forbidden`, `timeout`, `syntax_error`, `unavailable`,
//! `reason_required`, `internal`). Audit + response envelope are handled by
//! `tools::audit_dispatch` — this file only does the compute step.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, Decision};
use crate::config::{Action, ConfigFile, Database, Server};
use crate::exec::sql_guard;
use crate::exec::{self, ExecError, PoolRegistry};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{AuditHeader, Outcome, audit_dispatch, tool_error, tool_success};

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

pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    state_db: Option<&PgPool>,
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

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: Some(&args.sql),
    };
    let work = compute_outcome(id.clone(), identity, config, registry, &args);
    audit_dispatch(id, identity, state_db, header, work).await
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

    // Defense-in-depth on top of the read-only role: reject writes / DDL /
    // multi-statement before they ever hit the pool. See exec::sql_guard.
    if let Err(err) = sql_guard::is_read_only(&args.sql) {
        return Outcome {
            response: tool_error(
                id,
                "forbidden_sql",
                &format!("SQL rejected by gateway: {err}"),
            ),
            code: "forbidden_sql",
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
            // (which round-trips), so serialization is practically infallible
            // — but CLAUDE.md bans `expect` on the hot path, so fall through
            // to a typed internal error instead of panicking.
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
                response: tool_success(id, text),
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
}
