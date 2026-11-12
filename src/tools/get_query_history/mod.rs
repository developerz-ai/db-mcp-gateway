//! `get_query_history` — return *the caller's own* recent queries against a
//! configured `(server, database)` by reading the `audit_calls` table in the
//! state DB.
//!
//! SECURITY-CRITICAL (CLAUDE.md "Security review required"): this is the one
//! tool that reads *audit* data, so a scoping bug leaks other users' SQL —
//! and their SQL can carry sensitive literals. The filter is on the
//! SSO-verified `identity.user_sub` from the session middleware, NEVER on a
//! client-supplied `user` field. `#[serde(deny_unknown_fields)]` on
//! `Arguments` makes the contract explicit: any attempt to pass a `user`
//! argument is rejected at the JSON-RPC boundary with `invalid_params`,
//! before the request ever reaches the audit row.
//!
//! Audit + response envelope are handled by `tools::audit_dispatch` — this
//! file only does the compute step. The tool call itself is audited like any
//! other dispatch (the `outcome` row carries `tool = "get_query_history"`,
//! `server`/`database` from arguments, and `sql = NULL`).

mod args;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::authz::{self, Decision};
use crate::config::{Action, Grant};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, audit_outcome, error_outcome, run_audited, success_outcome,
};
pub use args::Arguments;
use args::{effective_limit, invalid_arguments_outcome, limit_was_clamped, parse_since};

const TOOL_NAME: &str = "get_query_history";

/// One row in the history response. Re-exported from the audit module so
/// the wire contract lives next to the SQL that produces it.
pub use crate::audit::HistoryEntry;

#[derive(Debug, Serialize)]
struct SuccessPayload {
    entries: Vec<HistoryEntry>,
    /// Whether the caller's `limit` was lowered by the gateway ceiling.
    ///
    /// This reports a *clamp*, not "more entries exist". A caller who asks
    /// for 10 of their 50 entries gets 10 with `truncated: false` — nothing
    /// was withheld beyond what they asked for. Only a request above
    /// `GATEWAY_ROW_LIMIT_CEILING` sets it. Agents that want more history
    /// should widen `since` rather than raise `limit`.
    truncated: bool,
}

/// The validated query window: `since` parsed, `limit` clamped.
#[derive(Debug, Clone, Copy)]
struct Window {
    since: Option<DateTime<Utc>>,
    limit: u32,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match arguments.map(serde_json::from_value::<Arguments>) {
        Some(Ok(a)) => a,
        _ => {
            return Response::error(
                id,
                ErrorObject::invalid_params(
                    "get_query_history requires `server` and `database` arguments",
                ),
            );
        }
    };

    // Build the header before any post-deserialisation validation so a
    // `since` / `limit` rejection is still audited. Missing that row would
    // leave the boundary probes (a caller sweeping bad `limit` values
    // against another user's server) undetectable — .coderabbit.yaml
    // §src/audit: "flag any code path that completes a tool call without an
    // audit row".
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        // No SQL on this tool — audit `sql` stays NULL.
        sql: None,
        reason: None,
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };

    let Ok(since) = parse_since(args.since.as_deref()) else {
        let outcome = invalid_arguments_outcome(
            id.clone(),
            "`since` must be an RFC 3339 timestamp (e.g. 2026-08-05T00:00:00Z)",
        );
        return audit_outcome(ctx, id, header, outcome).await;
    };
    // The advertised schema declares `"limit": { "minimum": 1 }`; enforce it
    // here so the typed value carries the constraint. Left unchecked, a
    // `limit: 0` flows through as an empty `entries` array — a wrong answer
    // ("you have no history") dressed as a right one, which is worse than an
    // error. Validated once, at the edge, like `since`, and audited the same
    // way so a `limit: 0` sweep leaves a trail.
    if args.limit == Some(0) {
        let outcome = invalid_arguments_outcome(id.clone(), "`limit` must be at least 1");
        return audit_outcome(ctx, id, header, outcome).await;
    }
    let window = Window {
        since,
        limit: effective_limit(args.limit),
    };
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, args, window).await
    })
    .await
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    args: &Arguments,
    window: Window,
) -> Outcome {
    // Server+database must exist in config — same gate as run_query. A
    // missing target short-circuits to `forbidden`, never to "no rows"
    // (which would let a misconfigured client get an empty list back and
    // not know why).
    let forbidden = |id| {
        error_outcome(
            id,
            OutcomeCode::Forbidden,
            "no grants for this server/database",
        )
    };
    let Some(server) = ctx.config.servers.iter().find(|s| s.name == args.server) else {
        return forbidden(id);
    };
    if !server.databases.iter().any(|d| d.name == args.database) {
        return forbidden(id);
    }

    // `history_read` is its own grant — `query_read` does NOT imply it
    // (resolved in #170). A caller without an explicit `history_read` grant
    // for `(server, database)` is denied; an inert grant is documented as
    // acceptable (see #169 body + spec 06 §"history_read").
    let decision = authz::evaluate_effective(
        ctx.identity,
        Action::HistoryRead,
        &args.server,
        &args.database,
        &ctx.config.permissions,
        db_grants,
    );
    let Decision::Allow { .. } = decision else {
        return forbidden(id);
    };

    // Defense-in-depth, not a live path: `audit_dispatch` refuses a dispatch
    // with no state DB before it ever polls this future, so today nothing
    // reaches here. Kept for the same reason `AdapterRegistry`'s
    // `UnsupportedAdapter` arm is kept behind config validation — the guard
    // is one refactor away from mattering, and a `compute_outcome` that
    // silently assumed a pool would be a worse failure than a dead branch.
    let Some(state_db) = ctx.state_db else {
        return error_outcome(id, OutcomeCode::Unavailable, "state DB unavailable");
    };

    let entries = match crate::state::audit::select_user_history(
        state_db,
        &ctx.identity.user_sub,
        &args.server,
        &args.database,
        window.since,
        window.limit,
    )
    .await
    {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(%err, "history query failed");
            return error_outcome(id, OutcomeCode::Internal, "history query failed");
        }
    };

    let truncated = limit_was_clamped(args.limit, window.limit);
    let text = match serde_json::to_string(&SuccessPayload { entries, truncated }) {
        Ok(t) => t,
        Err(_) => return error_outcome(id, OutcomeCode::Internal, "failed to serialize result"),
    };
    success_outcome(id, text, None, None, Some(truncated))
}
