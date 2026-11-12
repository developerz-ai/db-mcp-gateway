//! The per-DB tool preamble: find the `(server, database)` the caller named,
//! authorize the action on it, and apply the grant's constraints.

use crate::audit::{self, CallIntent};
use crate::authz::{self, Decision};
use crate::config::{Action, Constraints, Database, Grant, Server};
use crate::exec::sql_guard::Access;

use super::ToolCtx;
use super::audit_dispatch::{Outcome, OutcomeCode, error_outcome};

/// A configured target the caller holds a grant on, with the merged
/// constraints of every grant that applies (most restrictive wins).
#[derive(Debug)]
pub(super) struct Target<'a> {
    pub server: &'a Server,
    pub database: &'a Database,
    pub constraints: Constraints,
}

/// Resolve `(server, database)` and authorize `action` on it. An unknown
/// target and a denied one both yield `None`, so a caller cannot probe for
/// names: the tool answers [`forbidden`] either way.
pub(super) fn resolve_target<'a>(
    ctx: ToolCtx<'a>,
    db_grants: &[Grant],
    action: Action,
    server_name: &str,
    database_name: &str,
) -> Option<Target<'a>> {
    let server = ctx.config.servers.iter().find(|s| s.name == server_name)?;
    let database = server.databases.iter().find(|d| d.name == database_name)?;
    let decision = authz::evaluate_effective(
        ctx.identity,
        action,
        &server.name,
        &database.name,
        &ctx.config.permissions,
        db_grants,
    );
    match decision {
        Decision::Allow { constraints } => Some(Target {
            server,
            database,
            constraints,
        }),
        Decision::Deny => None,
    }
}

/// The one answer for an unknown or unauthorized target.
pub(super) fn forbidden() -> Outcome {
    error_outcome(OutcomeCode::Forbidden, "no grants for this server/database")
}

/// Commit the intent row for a call about to reach `target` — phase one of
/// the two-phase audit. Every tool calls this after authz and before it
/// opens the adapter; `Err` carries the `audit_unavailable` outcome and the
/// target call MUST NOT happen.
pub(super) async fn record_intent(
    ctx: ToolCtx<'_>,
    tool: &'static str,
    target: &Target<'_>,
    access: Access,
) -> Result<(), Box<Outcome>> {
    let intent = CallIntent {
        request_id: ctx.request.request_id,
        user_sub: &ctx.identity.user_sub,
        user_email: &ctx.identity.user_email,
        tool,
        server: &target.server.name,
        database: &target.database.name,
        db_type: Some(super::db_type_label(target.server.kind)),
        access,
    };
    audit::intent::record(ctx.state_db, &intent)
        .await
        .map_err(|err| {
            tracing::error!(
                %err,
                class = %err.class(),
                request_id = %ctx.request.request_id,
                tool,
                "audit intent write failed; refusing target call"
            );
            Box::new(error_outcome(
                OutcomeCode::AuditUnavailable,
                "audit log unavailable; request refused",
            ))
        })
}

/// `Err` with the `reason_required` outcome when the grant demands a reason
/// and the caller gave none (or an empty one). Applies to every tool that
/// reaches the target DB, so no tool is a reason-free side door.
pub(super) fn ensure_reason(
    constraints: &Constraints,
    reason: Option<&str>,
) -> Result<(), Box<Outcome>> {
    if constraints.require_reason && reason.is_none_or(str::is_empty) {
        return Err(Box::new(error_outcome(
            OutcomeCode::ReasonRequired,
            "policy requires a `reason` for this server/database",
        )));
    }
    Ok(())
}

/// `min(caller.unwrap_or(default), grant.unwrap_or(CEILING), CEILING)`.
/// The grant is clamped to [`super::GATEWAY_ROW_LIMIT_CEILING`] first so a
/// grant that declines to set `row_limit` (or one that names a value above
/// the ceiling) still bounds the caller's request — an absent grant used to
/// mean "whatever the caller asks for," including a hostile `limit` near
/// `u32::MAX`.
pub(super) fn effective_row_limit(caller: Option<u32>, grant: Option<u32>, default: u32) -> u32 {
    let grant_capped = grant
        .unwrap_or(super::GATEWAY_ROW_LIMIT_CEILING)
        .min(super::GATEWAY_ROW_LIMIT_CEILING);
    caller.unwrap_or(default).min(grant_capped)
}

#[cfg(test)]
mod tests {
    use super::super::GATEWAY_ROW_LIMIT_CEILING as CEILING;
    use super::*;

    const DEFAULT: u32 = 1000;

    #[test]
    fn effective_row_limit_takes_smaller() {
        assert_eq!(effective_row_limit(Some(10), Some(5), DEFAULT), 5);
        assert_eq!(effective_row_limit(Some(5), Some(10), DEFAULT), 5);
        assert_eq!(effective_row_limit(Some(50), None, DEFAULT), 50);
        assert_eq!(effective_row_limit(None, Some(20), DEFAULT), 20);
        assert_eq!(effective_row_limit(None, None, DEFAULT), DEFAULT);
        assert_eq!(effective_row_limit(None, None, 10), 10);
    }

    /// Regression for the #136 audit finding "caller `limit` unbounded when
    /// the grant sets no `row_limit`": an absent grant must still clamp to
    /// the gateway ceiling, not pass the caller's raw request straight through.
    #[test]
    fn effective_row_limit_clamps_to_gateway_ceiling_when_grant_is_silent() {
        assert_eq!(effective_row_limit(Some(u32::MAX), None, DEFAULT), CEILING);
        assert_eq!(
            effective_row_limit(Some(4_000_000_000), None, DEFAULT),
            CEILING
        );
    }

    /// A grant naming a `row_limit` above the ceiling must still be clamped
    /// down — a grant can only tighten the ceiling, never loosen past it.
    #[test]
    fn effective_row_limit_clamps_grant_above_ceiling() {
        assert_eq!(
            effective_row_limit(Some(u32::MAX), Some(u32::MAX), DEFAULT),
            CEILING
        );
    }

    /// A tight grant still wins even against a hostile caller request.
    #[test]
    fn effective_row_limit_grant_still_wins_under_hostile_caller_request() {
        assert_eq!(effective_row_limit(Some(u32::MAX), Some(7), DEFAULT), 7);
    }

    #[test]
    fn ensure_reason_only_rejects_when_required_and_missing() {
        let required = Constraints {
            require_reason: true,
            ..Constraints::default()
        };
        for missing in [None, Some("")] {
            let rejected = ensure_reason(&required, missing).expect_err("rejects");
            assert_eq!(rejected.code, OutcomeCode::ReasonRequired);
        }
        assert!(ensure_reason(&required, Some("incident-42")).is_ok());
        assert!(ensure_reason(&Constraints::default(), None).is_ok());
    }
}
