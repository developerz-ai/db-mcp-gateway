//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit` + `truncated` flag).
//!
//! Audit + response envelope are handled by `tools::audit_dispatch` — this
//! file only does the compute step.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, Decision, PermissionsCache, cache::load_or_empty};
use crate::config::{Action, ConfigFile, Database, Grant, Server};
use crate::exec::sql_guard;
use crate::exec::{self, ExecError, PoolRegistry};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, error_outcome, success_outcome,
};

const TOOL_NAME: &str = "run_query";

/// Hard floor on result rows when no grant constraint and no caller limit
/// apply. Spec 03 §"Results are size-capped".
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

#[allow(clippy::too_many_arguments)]
pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    permissions_cache: Option<&PermissionsCache>,
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
        reason: args.reason.as_deref(),
    };
    let db_grants = match load_or_empty(permissions_cache, identity).await {
        Ok(g) => g,
        Err(err) => {
            tracing::error!(%err, "permissions cache load failed");
            let resp = error_outcome(id.clone(), "internal", "permissions_cache_load_failed");
            let work = async move { resp };
            return audit_dispatch(id, identity, state_db, request_ctx, header, work).await;
        }
    };
    let work = compute_outcome(id.clone(), identity, config, registry, &db_grants, &args);
    audit_dispatch(id, identity, state_db, request_ctx, header, work).await
}

async fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &PoolRegistry,
    db_grants: &[Grant],
    args: &Arguments,
) -> Outcome {
    let Some((server, database)) = find_server_db(config, &args.server, &args.database) else {
        return error_outcome(id, "forbidden", "no grants for this server/database");
    };

    let decision = authz::evaluate_effective(
        identity,
        Action::QueryRead,
        &server.name,
        &database.name,
        &config.permissions,
        db_grants,
    );
    let constraints = match decision {
        Decision::Allow { constraints } => constraints,
        Decision::Deny => {
            return error_outcome(id, "forbidden", "no grants for this server/database");
        }
    };

    if constraints.require_reason && args.reason.as_deref().is_none_or(str::is_empty) {
        return error_outcome(
            id,
            "reason_required",
            "policy requires a `reason` for this server/database",
        );
    }

    // Defense-in-depth on top of the read-only role: reject writes / DDL /
    // multi-statement before they ever hit the pool. See exec::sql_guard.
    if let Err(err) = sql_guard::is_read_only(&args.sql) {
        return error_outcome(
            id,
            "forbidden_sql",
            &format!("SQL rejected by gateway: {err}"),
        );
    }

    let row_limit = effective_row_limit(args.limit, constraints.row_limit);
    let timeout_ms = constraints.statement_timeout_ms;

    tracing::info!(
        request_id = %id,
        user_sub = %identity.user_sub,
        server = %server.name,
        db = %database.name,
        row_limit,
        timeout_ms = ?timeout_ms,
        "tool.run_query.dispatch"
    );

    // Start the wall clock BEFORE pool open so error paths (timeout,
    // unavailable, syntax_error) still surface `duration_ms` in the audit
    // row — spec 07 requires it for every tool invocation.
    let started = Instant::now();
    let pool = match registry.get_or_open(server, database).await {
        Ok(p) => p,
        Err(err) => return outcome_from_exec_error(id, err, started),
    };

    match exec::run_query(&pool, &args.sql, timeout_ms, row_limit).await {
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
                Err(_) => return error_outcome(id, "internal", "failed to serialize result"),
            };
            success_outcome(id, text, Some(elapsed), Some(row_count), Some(truncated))
        }
        Err(err) => outcome_from_exec_error(id, err, started),
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

fn outcome_from_exec_error(id: Value, err: ExecError, started: Instant) -> Outcome {
    let (code, message) = match err {
        ExecError::Timeout => ("timeout", "query exceeded the configured statement_timeout"),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", "the target DB rejected the SQL"),
        ExecError::PasswordUnresolved { .. } => ("internal", "server-side configuration error"),
    };
    let mut outcome = error_outcome(id, code, message);
    outcome.elapsed_ms = Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX));
    outcome
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
