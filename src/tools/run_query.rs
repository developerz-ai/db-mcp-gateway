//! `run_query` — execute SQL under the caller's grants, with timeout and row
//! caps enforced both at the DB (via `SET LOCAL statement_timeout`) and at
//! the gateway (early stop after `row_limit` + `truncated` flag).
//!
//! Audit + response envelope are handled by `tools::audit_dispatch` — this
//! file only does the compute step.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::intent::WRITE_MAY_HAVE_COMMITTED;
use crate::config::{Action, Grant, ServerKind};
use crate::exec::{Access, ExecQuery, ExecResult, GuardedSql};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, WriteEffect, error_outcome,
    invalid_arguments, outcome_from_exec_error, reject_arguments, run_audited, success_outcome,
};
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
}

#[derive(Debug, Serialize)]
struct SuccessPayload<'a> {
    columns: &'a [String],
    rows: &'a [Vec<Value>],
    truncated: bool,
    elapsed_ms: u64,
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
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
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

    // Defense-in-depth on top of the DB role: the guard refuses anything the
    // grant doesn't cover before it hits the pool, and names the access the
    // statement itself needs — so a write-tier caller's SELECT still runs as
    // the read role. Mongo commands are not SQL: `MongoAdapter::execute` runs
    // its own read-only rejector, and Mongo writes are not offered at all.
    let access = match server.kind {
        ServerKind::Postgres => match statement_access(&args.sql, writes_allowed) {
            Ok(access) => access,
            Err(rejected) => return *rejected,
        },
        ServerKind::Mysql | ServerKind::Mssql | ServerKind::Mongo => Access::ReadOnly,
    };
    if args.dry_run && access != Access::ReadWrite {
        return invalid_arguments(id, DRY_RUN_NEEDS_WRITE);
    }

    let row_limit = effective_row_limit(args.limit, constraints.row_limit, DEFAULT_ROW_LIMIT);
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

    if let Err(refused) = record_intent(ctx, header, &target, access).await {
        return *refused;
    }

    // Start the wall clock BEFORE pool open so error paths (timeout,
    // unavailable, syntax_error) still surface `duration_ms` in the audit
    // row — spec 07 requires it for every tool invocation.
    let started = Instant::now();
    let adapter = match ctx.registry.get_or_open(server, database).await {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };

    let query = ExecQuery {
        sql: &args.sql,
        binds: &[],
        statement_timeout_ms: timeout_ms,
        row_limit,
        access,
        dry_run: args.dry_run,
        request_id: ctx.request.request_id,
    };
    let (mut outcome, rows_affected) = match adapter.execute(query).await {
        Ok(result) => (
            result_outcome(id, &result, args.dry_run),
            result.rows_affected,
        ),
        Err(err) => (outcome_from_exec_error(err, started, &ERROR_MESSAGES), None),
    };
    if access == Access::ReadWrite {
        outcome.write = Some(WriteEffect {
            rows_affected: rows_affected.map(|rows| i64::try_from(rows).unwrap_or(i64::MAX)),
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

/// The access `sql` needs, after the guard at the caller's grant level:
/// `ReadWrite` only for a data write under a `query_write` grant.
fn statement_access(sql: &str, writes_allowed: bool) -> Result<Access, Box<Outcome>> {
    let grant = if writes_allowed {
        Access::ReadWrite
    } else {
        Access::ReadOnly
    };
    GuardedSql::parse(sql, grant)
        .map(|guarded| guarded.required_access())
        .map_err(|err| {
            Box::new(error_outcome(
                OutcomeCode::ForbiddenSql,
                &format!("SQL rejected by gateway: {err}"),
            ))
        })
}

fn result_outcome(id: Value, result: &ExecResult, dry_run: bool) -> Outcome {
    let elapsed = i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX);
    let row_count = i64::try_from(result.rows.len()).unwrap_or(i64::MAX);
    let payload = SuccessPayload {
        columns: &result.columns,
        rows: &result.rows,
        truncated: result.truncated,
        elapsed_ms: result.elapsed_ms,
        rows_affected: result.rows_affected,
        dry_run,
    };
    let Ok(text) = serde_json::to_string(&payload) else {
        return error_outcome(OutcomeCode::Internal, "failed to serialize result");
    };
    let mut outcome = success_outcome(
        id,
        text,
        Some(elapsed),
        Some(row_count),
        Some(result.truncated),
    );
    if dry_run {
        outcome.code = OutcomeCode::DryRun;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timed_out_write_says_it_may_have_committed() {
        let mut outcome = error_outcome(OutcomeCode::Timeout, ERROR_MESSAGES.timeout);
        note_indeterminate_write(&mut outcome, false);
        let message = outcome.error_message.unwrap_or_default();
        assert!(message.contains(WRITE_MAY_HAVE_COMMITTED), "{message}");
    }

    #[test]
    fn a_cancelled_write_says_it_may_have_committed() {
        let mut outcome = error_outcome(
            OutcomeCode::Cancelled,
            "query was cancelled by cancel_query",
        );
        note_indeterminate_write(&mut outcome, false);
        let message = outcome.error_message.unwrap_or_default();
        assert!(message.contains(WRITE_MAY_HAVE_COMMITTED), "{message}");
    }

    #[test]
    fn a_rejected_write_is_not_called_indeterminate() {
        let mut outcome = error_outcome(OutcomeCode::SyntaxError, ERROR_MESSAGES.sql_rejected);
        note_indeterminate_write(&mut outcome, false);
        assert_eq!(
            outcome.error_message.as_deref(),
            Some(ERROR_MESSAGES.sql_rejected)
        );
    }

    #[test]
    fn a_dry_run_write_is_never_called_indeterminate() {
        // A dry_run rolls the transaction back (exec/pg/run.rs), so even a
        // cut-off one cannot have committed anything.
        let mut outcome = error_outcome(OutcomeCode::Timeout, ERROR_MESSAGES.timeout);
        note_indeterminate_write(&mut outcome, true);
        assert_eq!(
            outcome.error_message.as_deref(),
            Some(ERROR_MESSAGES.timeout)
        );
    }
}
