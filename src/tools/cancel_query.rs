//! `cancel_query` — stop one of the caller's own running statements by its
//! gateway `request_id`.
//!
//! Action: `QueryRead` on the database the statement runs on. Ownership is
//! checked against the intent row every target call commits first: a
//! `request_id` that is not the caller's on this `(server, database)` answers
//! `forbidden`, the same as an unknown one, so ids cannot be probed. The
//! cancelled call fails with `cancelled` and writes its own audit row.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::config::{Action, Grant};
use crate::exec::Access;
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, audit_outcome, error_outcome,
    invalid_arguments, outcome_from_exec_error, reject_arguments, run_audited, success_outcome,
};
use super::target::{Target, ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = super::CANCEL_QUERY;
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "cancel request exceeded statement_timeout",
    sql_rejected: "cancel request was rejected",
    forbidden_prefix: "cancel request",
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    pub request_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuccessPayload {
    /// `false` when the request had already finished.
    cancelled: bool,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };
    // The audit row's `sql` names the request this call targets.
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: Some(&args.request_id),
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };
    let Ok(victim) = Uuid::parse_str(&args.request_id) else {
        let outcome = invalid_arguments(id.clone(), "`request_id` must be a UUID");
        return audit_outcome(ctx, id, header, outcome).await;
    };
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args, victim).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
    victim: Uuid,
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
    if let Err(rejected) = ensure_reason(&target.constraints, args.reason.as_deref()) {
        return *rejected;
    }
    if let Err(rejected) = ensure_owned(ctx, &target, victim).await {
        return *rejected;
    }
    if let Err(refused) = record_intent(ctx, header, &target, Access::ReadOnly).await {
        return *refused;
    }

    let started = Instant::now();
    let adapter = match ctx
        .registry
        .get_or_open(target.server, target.database)
        .await
    {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };
    match adapter.cancel_request(victim).await {
        Ok(cancelled) => {
            let elapsed = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
            let Ok(text) = serde_json::to_string(&SuccessPayload { cancelled }) else {
                return error_outcome(OutcomeCode::Internal, "failed to serialize result");
            };
            success_outcome(id, text, Some(elapsed), None, None)
        }
        Err(err) => outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    }
}

/// `forbidden` unless `victim` is one of the caller's own requests on
/// `target` — never another identity's, even one holding the same grants.
async fn ensure_owned(
    ctx: ToolCtx<'_>,
    target: &Target<'_>,
    victim: Uuid,
) -> Result<(), Box<Outcome>> {
    let owned = crate::state::audit::select_owned_request_ids(
        ctx.state_db,
        &ctx.identity.user_sub,
        &target.server.name,
        &target.database.name,
        &[victim.to_string()],
    )
    .await
    .map_err(|err| {
        tracing::error!(
            class = %crate::state::connect_error_class(&err),
            "cancel ownership lookup failed"
        );
        Box::new(error_outcome(
            OutcomeCode::Internal,
            "cancel ownership lookup failed",
        ))
    })?;
    if owned.is_empty() {
        return Err(Box::new(error_outcome(
            OutcomeCode::Forbidden,
            "no request of yours with that request_id on this server/database",
        )));
    }
    Ok(())
}
