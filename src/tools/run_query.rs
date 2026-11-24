//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit` + `truncated` flag).
//!
//! Audit + response envelope are handled by `tools::audit_dispatch` — this
//! file only does the compute step.

use std::num::NonZeroU32;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::intent::WRITE_MAY_HAVE_COMMITTED;
use crate::config::{Action, Grant, ServerKind};
use crate::exec::{Access, ExecQuery, ExecResult, QueryParam};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::{LIMIT_AT_LEAST_ONE, parse_arguments};
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, WriteEffect, audit_outcome,
    invalid_arguments, note_timeout_limit, outcome_from_exec_error, reject_arguments,
    run_audited_with_params, write_state,
};
use super::query_params::{parse_params, unsupported_for};
use super::tabular::caps::{ByteCaps, MaxBytes, RowLimit};
use super::tabular::{RowShaping, rows_outcome};
use super::target::{effective_row_limit, ensure_reason, forbidden, record_intent, resolve_target};

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
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub sql: String,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Run a write, report `rows_affected`, roll it back.
    #[serde(default)]
    pub dry_run: bool,
    /// Cap on the JSON size of the returned rows (spec 03 §Results).
    #[serde(default)]
    pub max_bytes: Option<MaxBytes>,
    /// Cap on one cell's JSON size; a larger cell becomes a marker.
    #[serde(default)]
    pub max_cell_bytes: Option<NonZeroU32>,
    /// Values bound to `$1..$n` (Postgres only); see `query_params`.
    #[serde(default)]
    pub params: Vec<Value>,
}

/// `run_query`'s fields beside the shared row-result ones.
#[derive(Debug, Serialize)]
struct WriteFields {
    /// Rows the write changed; absent for a read.
    #[serde(skip_serializing_if = "Option::is_none")]
    rows_affected: Option<u64>,
    /// The write was rolled back.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    dry_run: bool,
}

const DRY_RUN_NEEDS_WRITE: &str =
    "`dry_run` applies only to an INSERT/UPDATE/DELETE under a query_write grant";

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: Some(&args.sql),
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };
    if args.limit == Some(0) {
        let outcome = invalid_arguments(id.clone(), LIMIT_AT_LEAST_ONE);
        return audit_outcome(ctx, id, header, outcome).await;
    }
    let params = match parse_params(&args.params) {
        Ok(params) => params,
        Err(message) => {
            let outcome = invalid_arguments(id.clone(), &message);
            return audit_outcome(ctx, id, header, outcome).await;
        }
    };
    let (args, params) = (&args, &params);
    let stored = (!args.params.is_empty()).then_some(args.params.as_slice());
    run_audited_with_params(ctx, id, header, stored, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args, params).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
    params: &[QueryParam],
) -> Outcome {
    // Constraints come from the read-level merge: it matches *every* grant that
    // applies to this (server, db) — `query_write` included, since it implies
    // `query_read` — so the most-restrictive value across all of them always
    // wins, and a write can never dodge a tighter read grant's caps.
    let Some(target) = resolve_target(
        ctx,
        db_grants,
        Action::QueryRead,
        &args.server,
        &args.database,
    ) else {
        return forbidden();
    };
    let (server, database, constraints) = (target.server, target.database, &target.constraints);

    // A separate `query_write` check decides whether data writes are permitted.
    // Only `query_write` grants satisfy it (`query_read` does not imply write),
    // so read-only callers stay on the read-only guard.
    let writes_allowed = resolve_target(
        ctx,
        db_grants,
        Action::QueryWrite,
        &server.name,
        &database.name,
    )
    .is_some();

    if let Err(rejected) = ensure_reason(constraints, args.reason.as_deref()) {
        return *rejected;
    }
    if let Some(message) = unsupported_for(server.kind).filter(|_| !params.is_empty()) {
        return invalid_arguments(id, &message);
    }

    // Defense-in-depth on top of the DB role: the guard refuses anything the
    // grant doesn't cover before it hits the pool, and names the access the
    // statement itself needs — so a write-tier caller's SELECT still runs as
    // the read role. Mongo and Redis commands are not SQL: each adapter runs
    // its own read-only rejector (Mongo writes are not offered at all), but
    // the command is checked here too, so a malformed one is
    // `invalid_arguments`.
    let access = match server.kind {
        ServerKind::Postgres => match statement_access(&args.sql, writes_allowed) {
            Ok(access) => access,
            Err(rejected) => return *rejected,
        },
        ServerKind::Redis => match redis_access(id.clone(), &args.sql) {
            Ok(access) => access,
            Err(rejected) => return *rejected,
        },
        ServerKind::Mongo => match mongo_access(id.clone(), &args.sql) {
            Ok(access) => access,
            Err(rejected) => return *rejected,
        },
        ServerKind::Mysql | ServerKind::Mssql => Access::ReadOnly,
    };
    if args.dry_run && access != Access::ReadWrite {
        return invalid_arguments(id, DRY_RUN_NEEDS_WRITE);
    }

    let row_limit = effective_row_limit(args.limit, constraints.row_limit, DEFAULT_ROW_LIMIT);
    let shaping = RowShaping {
        limit: RowLimit {
            effective: row_limit,
            asked: args.limit.unwrap_or(DEFAULT_ROW_LIMIT),
        },
        caps: ByteCaps {
            max_bytes: args.max_bytes,
            max_cell_bytes: args.max_cell_bytes,
        },
        kind: server.kind,
    };
    let timeout_ms = constraints.statement_timeout_ms;

    // Emit `request_id` explicitly. The production formatter (main.rs) sets
    // `with_current_span(false)` + `with_span_list(false)`, so span fields
    // from the enclosing `tool_dispatch` span never render — every event
    // that needs to correlate with a Loki log line or audit row has to
    // carry `request_id` on itself. The chokepoint's "tool dispatched"
    // line does; so must this one.
    tracing::info!(
        request_id = %ctx.request.request_id,
        user_sub = %ctx.identity.user_sub,
        server = %server.name,
        db = %database.name,
        row_limit,
        timeout_ms = ?timeout_ms,
        "tool.run_query.dispatch"
    );

    // The intent keeps the params too, so an `abandoned` row has them.
    let stored = (!args.params.is_empty()).then_some(args.params.as_slice());
    if let Err(refused) = record_intent(ctx, header, &target, access, stored).await {
        return *refused;
    }

    // Start the wall clock BEFORE pool open so error paths (timeout,
    // unavailable, syntax_error) still surface `duration_ms` in the audit
    // row — spec 07 requires it for every tool invocation.
    let started = Instant::now();
    let query = ExecQuery {
        sql: &args.sql,
        binds: &[],
        statement_timeout_ms: timeout_ms,
        row_limit,
        access,
        dry_run: args.dry_run,
        request_id: ctx.request.request_id,
    };
    let executed = match ctx.registry.get_or_open(server, database).await {
        Ok(adapter) => adapter.execute_with_params(query, params).await,
        Err(err) => Err(err),
    };
    let state = write_state(&executed, args.dry_run);
    let (mut outcome, rows_affected) = match executed {
        Ok(result) => {
            let rows_affected = result.rows_affected;
            (
                result_outcome(id, result, shaping, args.dry_run),
                rows_affected,
            )
        }
        Err(err) => {
            let mut outcome = outcome_from_exec_error(err, started, &ERROR_MESSAGES);
            note_timeout_limit(&mut outcome, timeout_ms);
            (outcome, None)
        }
    };
    if access == Access::ReadWrite {
        outcome.write = Some(WriteEffect {
            rows_affected: rows_affected.map(|rows| i64::try_from(rows).unwrap_or(i64::MAX)),
            state,
        });
        note_indeterminate_write(&mut outcome, args.dry_run);
    }
    outcome
}

/// A write cut off by the deadline or `cancel_query` may have been cut off
/// mid-commit: say so in the client message and the audit row instead of
/// implying nothing happened. A `dry_run` write is exempt — it rolls the
/// transaction back and cannot commit, so its outcome is never
/// indeterminate.
fn note_indeterminate_write(outcome: &mut Outcome, dry_run: bool) {
    if dry_run || !matches!(outcome.code, OutcomeCode::Timeout | OutcomeCode::Cancelled) {
        return;
    }
    if let Some(message) = outcome.error_message.as_mut() {
        message.push_str(&format!(" ({WRITE_MAY_HAVE_COMMITTED})"));
    }
}

fn result_outcome(id: Value, result: ExecResult, shaping: RowShaping, dry_run: bool) -> Outcome {
    let fields = WriteFields {
        rows_affected: result.rows_affected,
        dry_run,
    };
    let mut outcome = rows_outcome(id, result, shaping, fields);
    if dry_run && outcome.code == OutcomeCode::Success {
        outcome.code = OutcomeCode::DryRun;
    }
    outcome
}

#[path = "run_query_access.rs"]
mod access;
use access::{mongo_access, redis_access, statement_access};

#[cfg(test)]
#[path = "run_query_tests.rs"]
mod tests;
