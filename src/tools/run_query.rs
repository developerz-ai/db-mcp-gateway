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
use crate::exec::{AdapterRegistry, ExecQuery};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, ToolErrorMessages, audit_dispatch, error_outcome,
    outcome_from_exec_error, success_outcome,
};

const TOOL_NAME: &str = "run_query";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "query exceeded the configured statement_timeout",
    sql_rejected: "the target DB rejected the SQL",
    forbidden_prefix: "query",
};

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
    registry: &AdapterRegistry,
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
        db_type: super::db_type_for_server(config, &args.server),
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
    let work = compute_outcome(
        id.clone(),
        identity,
        config,
        registry,
        &db_grants,
        request_ctx,
        &args,
    );
    audit_dispatch(id, identity, state_db, request_ctx, header, work).await
}

async fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    registry: &AdapterRegistry,
    db_grants: &[Grant],
    request_ctx: &RequestContext,
    args: &Arguments,
) -> Outcome {
    let Some((server, database)) = find_server_db(config, &args.server, &args.database) else {
        return error_outcome(id, "forbidden", "no grants for this server/database");
    };

    // Constraints come from the read-level merge: it matches *every* grant that
    // applies to this (server, db) — `query_write` included, since it implies
    // `query_read` — so the most-restrictive value across all of them always
    // wins, and a write can never dodge a tighter read grant's caps.
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

    // A separate `query_write` check decides whether data writes are permitted.
    // Only `query_write` grants satisfy it (`query_read` does not imply write),
    // so read-only callers stay on the read-only guard.
    let writes_allowed = matches!(
        authz::evaluate_effective(
            identity,
            Action::QueryWrite,
            &server.name,
            &database.name,
            &config.permissions,
            db_grants,
        ),
        Decision::Allow { .. }
    );
    let access = if writes_allowed {
        sql_guard::Access::ReadWrite
    } else {
        sql_guard::Access::ReadOnly
    };

    if constraints.require_reason && args.reason.as_deref().is_none_or(str::is_empty) {
        return error_outcome(
            id,
            "reason_required",
            "policy requires a `reason` for this server/database",
        );
    }

    // Defense-in-depth on top of the DB role: reject anything the grant doesn't
    // cover before it hits the pool. Read-only callers get `is_read_only`;
    // `query_write` callers additionally get single-statement INSERT/UPDATE/
    // DELETE — never schema mods. See exec::sql_guard.
    //
    // pg only: `sql_guard` is a SQL parser; mongo commands are JSON-shaped
    // BSON, not SQL. `MongoAdapter::execute` runs its own read-only
    // rejector (`src/exec/mongo/rejector.rs`) as the equivalent guard. Mongo
    // writes are not offered here — a `query_write` grant on a mongo DB still
    // hits the read-only rejector.
    if matches!(server.kind, crate::config::ServerKind::Postgres) {
        if let Err(err) = sql_guard::check_sql(&args.sql, access) {
            return error_outcome(
                id,
                "forbidden_sql",
                &format!("SQL rejected by gateway: {err}"),
            );
        }
    }

    let row_limit = effective_row_limit(args.limit, constraints.row_limit);
    let timeout_ms = constraints.statement_timeout_ms;

    // Emit `request_id` explicitly. The production formatter (main.rs) sets
    // `with_current_span(false)` + `with_span_list(false)`, so span fields
    // from the enclosing `tool_dispatch` span never render — every event
    // that needs to correlate with a Loki log line or audit row has to
    // carry `request_id` on itself. The chokepoint's "tool dispatched"
    // line does; so must this one.
    tracing::info!(
        request_id = %request_ctx.request_id,
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
    let adapter = match registry.get_or_open(server, database).await {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(id, err, started, &ERROR_MESSAGES),
    };

    let query = ExecQuery {
        sql: &args.sql,
        binds: &[],
        statement_timeout_ms: timeout_ms,
        row_limit,
    };
    match adapter.execute(query).await {
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
        Err(err) => outcome_from_exec_error(id, err, started, &ERROR_MESSAGES),
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
