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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, Decision, PermissionsCache, cache::load_or_empty};
use crate::config::{Action, ConfigFile};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, error_outcome, success_outcome,
};

const TOOL_NAME: &str = "get_query_history";
/// Hard floor on entries returned when no caller `limit` is supplied.
/// History is "recover context across sessions", not "bulk export" — small
/// by default keeps the response bounded and the agent's recovery loop
/// cheap.
const DEFAULT_HISTORY_LIMIT: u32 = 100;

/// Caller-supplied arguments. `deny_unknown_fields` is the security
/// guarantee behind the scoping promise above: an agent cannot smuggle a
/// `user` field through JSON-RPC to override the server-side identity. Any
/// unknown key is rejected with `invalid_params` before this code runs.
///
/// `since` is RFC 3339 (the MCP wire shape for `format: date-time`); we parse
/// at the edge so the audit row + downstream SQL see a typed instant.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One row in the history response. Re-exported from the audit module so
/// the wire contract lives next to the SQL that produces it.
pub use crate::audit::HistoryEntry;

#[derive(Debug, Serialize)]
struct SuccessPayload {
    entries: Vec<HistoryEntry>,
    /// True iff the caller asked for more than the effective ceiling — i.e.
    /// the response is capped and earlier entries exist beyond it. Agents
    /// can use this to widen the `since` window instead of raising `limit`.
    truncated: bool,
}

/// `effective = min(caller.unwrap_or(DEFAULT), GATEWAY_ROW_LIMIT_CEILING)`.
/// Same most-restrictive-wins posture as `run_query::effective_row_limit`,
/// minus the grant column: history is read-only against audit data, no
/// `row_limit` constraint applies. The ceiling is what bounds a hostile
/// caller from asking for `u32::MAX` rows and getting back the entire audit
/// table slice they happen to be entitled to.
fn effective_limit(caller: Option<u32>) -> u32 {
    caller
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .min(super::GATEWAY_ROW_LIMIT_CEILING)
}

/// Parse an RFC 3339 timestamp at the edge. Any failure becomes a typed
/// `invalid_params` so a malformed `since` doesn't silently mean "no filter"
/// (which would let a caller pull history beyond their intended window).
fn parse_since(value: Option<&str>) -> Result<Option<DateTime<Utc>>, ()> {
    let Some(raw) = value else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
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
                    "get_query_history requires `server` and `database` arguments",
                ),
            );
        }
    };

    let since = match parse_since(args.since.as_deref()) {
        Ok(ts) => ts,
        Err(()) => {
            return Response::error(
                id,
                ErrorObject::invalid_params(
                    "`since` must be an RFC 3339 timestamp (e.g. 2026-08-05T00:00:00Z)",
                ),
            );
        }
    };
    let limit = effective_limit(args.limit);

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        // No SQL on this tool — audit `sql` stays NULL.
        sql: None,
        reason: None,
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
        &db_grants,
        &args,
        since,
        limit,
        state_db,
    );
    audit_dispatch(id, identity, state_db, request_ctx, header, work).await
}

#[allow(clippy::too_many_arguments)]
async fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[crate::config::Grant],
    args: &Arguments,
    since: Option<DateTime<Utc>>,
    limit: u32,
    state_db: Option<&PgPool>,
) -> Outcome {
    // Server+database must exist in config — same gate as run_query. A
    // missing target short-circuits to `forbidden`, never to "no rows"
    // (which would let a misconfigured client get an empty list back and
    // not know why).
    let Some(server) = config.servers.iter().find(|s| s.name == args.server) else {
        return error_outcome(id, "forbidden", "no grants for this server/database");
    };
    if !server.databases.iter().any(|d| d.name == args.database) {
        return error_outcome(id, "forbidden", "no grants for this server/database");
    }

    // `history_read` is its own grant — `query_read` does NOT imply it
    // (resolved in #170). A caller without an explicit `history_read` grant
    // for `(server, database)` is denied; an inert grant is documented as
    // acceptable (see #169 body + spec 06 §"history_read").
    let decision = authz::evaluate_effective(
        identity,
        Action::HistoryRead,
        &args.server,
        &args.database,
        &config.permissions,
        db_grants,
    );
    let Decision::Allow { .. } = decision else {
        return error_outcome(id, "forbidden", "no grants for this server/database");
    };

    let Some(state_db) = state_db else {
        return error_outcome(id, "unavailable", "state DB unavailable");
    };

    let entries = match crate::audit::query_user_history(
        state_db,
        &identity.user_sub,
        &args.server,
        &args.database,
        since,
        limit,
    )
    .await
    {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(%err, "history query failed");
            return error_outcome(id, "internal", "history query failed");
        }
    };

    // `truncated = true` iff the caller asked for more than the effective
    // ceiling — i.e. the response is capped.
    let truncated = args.limit.is_some_and(|l| l > limit);
    let text = match serde_json::to_string(&SuccessPayload { entries, truncated }) {
        Ok(t) => t,
        Err(_) => return error_outcome(id, "internal", "failed to serialize result"),
    };
    success_outcome(id, text, None, None, Some(truncated))
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests — full real-DB coverage lives in
    //! `tests/get_query_history_real_db.rs`.

    use super::*;

    /// The ceiling clamp is the only thing that stands between a caller
    /// asking for `u32::MAX` rows and the audit table serving up a giant
    /// slice. Pin both branches of the clamp here.
    #[test]
    fn effective_limit_clamps_to_ceiling() {
        assert_eq!(
            effective_limit(Some(u32::MAX)),
            super::super::GATEWAY_ROW_LIMIT_CEILING
        );
        assert_eq!(
            effective_limit(Some(4_000_000_000)),
            super::super::GATEWAY_ROW_LIMIT_CEILING
        );
    }

    #[test]
    fn effective_limit_passes_through_small_values() {
        assert_eq!(effective_limit(Some(50)), 50);
        assert_eq!(effective_limit(Some(1)), 1);
    }

    #[test]
    fn effective_limit_uses_default_when_absent() {
        assert_eq!(effective_limit(None), DEFAULT_HISTORY_LIMIT);
    }

    /// `since` parsing is the edge that decides whether a malformed value
    /// silently drops the filter (= window widening = data exposure) or
    /// rejects the call. Pin both directions.
    #[test]
    fn parse_since_accepts_rfc3339_utc() {
        let ts = parse_since(Some("2026-08-05T00:00:00Z")).expect("parses");
        assert_eq!(
            ts.expect("Some"),
            DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn parse_since_accepts_rfc3339_with_offset() {
        let ts = parse_since(Some("2026-08-05T08:00:00+08:00")).expect("parses");
        assert_eq!(
            ts.expect("Some"),
            DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn parse_since_rejects_garbage() {
        assert!(parse_since(Some("yesterday")).is_err());
        assert!(parse_since(Some("")).is_err());
        assert!(parse_since(Some("2026-13-40")).is_err());
    }

    #[test]
    fn parse_since_none_is_none() {
        assert!(parse_since(None).unwrap().is_none());
    }

    /// THE SECURITY TEST. `deny_unknown_fields` is the type-level promise
    /// that no caller-supplied `user` (or any other identity override) can
    /// slip into the deserialized arguments. A regression that drops the
    /// attribute would compile cleanly but silently allow the bypass —
    /// pin it here.
    #[test]
    fn arguments_rejects_user_field_at_deserialize() {
        let json = serde_json::json!({
            "server": "prod",
            "database": "app",
            "user": "someone-else", // <- smuggling attempt
        });
        let result: Result<Arguments, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "Arguments must reject unknown `user` field — got {result:?}",
        );
    }

    #[test]
    fn arguments_accepts_canonical_shape() {
        let json = serde_json::json!({
            "server": "prod",
            "database": "app",
        });
        let args: Arguments = serde_json::from_value(json).expect("canonical parses");
        assert_eq!(args.server, "prod");
        assert_eq!(args.database, "app");
        assert!(args.since.is_none());
        assert!(args.limit.is_none());
    }

    #[test]
    fn arguments_accepts_optional_fields() {
        let json = serde_json::json!({
            "server": "prod",
            "database": "app",
            "since": "2026-08-05T00:00:00Z",
            "limit": 25,
        });
        let args: Arguments = serde_json::from_value(json).expect("full parses");
        assert_eq!(args.since.as_deref(), Some("2026-08-05T00:00:00Z"));
        assert_eq!(args.limit, Some(25));
    }
}
