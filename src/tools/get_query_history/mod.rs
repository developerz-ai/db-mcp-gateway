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
//!
//! Paging: at most [`args::HISTORY_LIMIT_CEILING`] entries per call, keyset
//! on `(occurred_at, id)`; `next_cursor` fetches the next older page.

mod args;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::audit::{HistoryCursor, HistoryQuery};
use crate::auth::Identity;
use crate::authz::{self, Decision};
use crate::config::{Action, ConfigFile, Grant};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, audit_outcome, error_outcome, invalid_arguments,
    reject_arguments, run_audited, success_outcome,
};
use super::target::{ensure_reason, forbidden};
pub use args::Arguments;
use args::{effective_limit, limit_was_clamped, parse_since};

const TOOL_NAME: &str = "get_query_history";

/// One row in the history response. Re-exported from the audit module so
/// the wire contract lives next to the SQL that produces it.
pub use crate::audit::HistoryEntry;

#[derive(Debug, Serialize)]
struct SuccessPayload {
    entries: Vec<HistoryEntry>,
    /// Whether the caller's `limit` was lowered by the page ceiling.
    ///
    /// This reports a *clamp*, not "more entries exist" — that is
    /// `next_cursor`. Only a request above `HISTORY_LIMIT_CEILING` sets it.
    truncated: bool,
    /// Pass back as `cursor` for the next older page; `null` on the last.
    next_cursor: Option<String>,
}

/// The validated query window: `since` and `cursor` parsed, `limit` clamped.
#[derive(Debug, Clone, Copy)]
struct Window {
    since: Option<DateTime<Utc>>,
    before: Option<HistoryCursor>,
    limit: u32,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match arguments.map(serde_json::from_value::<Arguments>) {
        Some(Ok(a)) => a,
        _ => {
            return reject_arguments(
                ctx,
                id,
                TOOL_NAME,
                "get_query_history requires `server` and `database` arguments",
            )
            .await;
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
        reason: args.reason.as_deref(),
        db_type: super::db_type_for_server(ctx.config, &args.server),
    };

    let Ok(since) = parse_since(args.since.as_deref()) else {
        let outcome = invalid_arguments(
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
        let outcome = invalid_arguments(id.clone(), "`limit` must be at least 1");
        return audit_outcome(ctx, id, header, outcome).await;
    }
    let before = match args.cursor.as_deref().map(HistoryCursor::parse).transpose() {
        Ok(before) => before,
        Err(err) => {
            let outcome = invalid_arguments(id.clone(), &err.to_string());
            return audit_outcome(ctx, id, header, outcome).await;
        }
    };
    let window = Window {
        since,
        before,
        limit: effective_limit(args.limit),
    };
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, args, window).await
    })
    .await
}

/// Server+database must exist in config — same gate as run_query: a
/// missing target is `forbidden`, never "no rows" (an empty list would hide
/// the misconfiguration). `history_read` is its own grant — `query_read`
/// does NOT imply it (#170). The merged constraints of the matching grants
/// apply as on every other tool: a grant demanding a reason is not a side
/// door here, since history returns the caller's SQL.
fn authorize(
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
    args: &Arguments,
) -> Result<(), Box<Outcome>> {
    let target_exists = config
        .servers
        .iter()
        .find(|s| s.name == args.server)
        .is_some_and(|s| s.databases.iter().any(|d| d.name == args.database));
    if !target_exists {
        return Err(Box::new(forbidden()));
    }
    let decision = authz::evaluate_effective(
        identity,
        Action::HistoryRead,
        &args.server,
        &args.database,
        &config.permissions,
        db_grants,
    );
    let Decision::Allow { constraints } = decision else {
        return Err(Box::new(forbidden()));
    };
    ensure_reason(&constraints, args.reason.as_deref())
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    args: &Arguments,
    window: Window,
) -> Outcome {
    if let Err(rejected) = authorize(ctx.identity, ctx.config, db_grants, args) {
        return *rejected;
    }

    let query = HistoryQuery {
        user_sub: &ctx.identity.user_sub,
        server: &args.server,
        database: &args.database,
        since: window.since,
        before: window.before,
        limit: window.limit,
    };
    let page = match crate::state::audit::select_user_history(ctx.state_db, &query).await {
        Ok(page) => page,
        Err(err) => {
            tracing::error!(
                class = %crate::state::connect_error_class(&err),
                "history query failed"
            );
            return error_outcome(OutcomeCode::Internal, "history query failed");
        }
    };

    let payload = SuccessPayload {
        entries: page.entries,
        truncated: limit_was_clamped(args.limit, window.limit),
        next_cursor: page.next.map(|cursor| cursor.encode()),
    };
    let truncated = payload.truncated;
    let text = match serde_json::to_string(&payload) {
        Ok(t) => t,
        Err(_) => return error_outcome(OutcomeCode::Internal, "failed to serialize result"),
    };
    success_outcome(id, text, None, None, Some(truncated))
}

#[cfg(test)]
mod authorize_tests {
    use super::*;
    use crate::auth::SessionId;

    const YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: prod
    host: prod.db.internal
    databases:
      - { name: app, role: ro, password: pw }

permissions:
  - group: auditors
    grants:
      - server: prod
        database: app
        action: history_read
        constraints:
          require_reason: true
  - group: readers
    grants:
      - { server: prod, database: app, action: history_read }
"#;

    fn identity(group: &str) -> Identity {
        Identity {
            session_id: SessionId::new(),
            user_sub: "u".to_string(),
            user_email: "u@example.com".to_string(),
            groups: vec![group.to_string()],
            issued_at: chrono::Utc::now(),
            kind: crate::auth::IdentityKind::Sso,
        }
    }

    fn args(reason: Option<&str>) -> Arguments {
        Arguments {
            server: "prod".into(),
            database: "app".into(),
            since: None,
            limit: None,
            cursor: None,
            reason: reason.map(str::to_string),
        }
    }

    fn rejected_code(group: &str, reason: Option<&str>) -> Option<OutcomeCode> {
        let config = ConfigFile::from_yaml_str(YAML).expect("yaml parses");
        authorize(&identity(group), &config, &[], &args(reason))
            .err()
            .map(|outcome| outcome.code)
    }

    /// Same code as `run_query`'s missing-reason path; an empty string is
    /// not a reason.
    #[test]
    fn require_reason_applies_to_history() {
        assert_eq!(
            rejected_code("auditors", None),
            Some(OutcomeCode::ReasonRequired)
        );
        assert_eq!(
            rejected_code("auditors", Some("")),
            Some(OutcomeCode::ReasonRequired)
        );
        assert_eq!(rejected_code("auditors", Some("INC-7 review")), None);
    }

    #[test]
    fn no_reason_needed_without_the_constraint() {
        assert_eq!(rejected_code("readers", None), None);
    }

    #[test]
    fn no_grant_is_forbidden_before_any_reason_check() {
        assert_eq!(rejected_code("nobody", None), Some(OutcomeCode::Forbidden));
    }
}
