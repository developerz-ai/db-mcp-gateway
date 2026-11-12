//! Argument contract for `get_query_history`: the deserialised shape and the
//! post-deserialisation checks (`since`, `limit`) applied once at the edge.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::tools::GATEWAY_ROW_LIMIT_CEILING;
use crate::tools::audit_dispatch::{Outcome, OutcomeCode};
use crate::transport::jsonrpc::{ErrorObject, Response};

/// Hard floor on entries returned when no caller `limit` is supplied.
/// History is "recover context across sessions", not "bulk export" — small
/// by default keeps the response bounded and the agent's recovery loop
/// cheap.
const DEFAULT_HISTORY_LIMIT: u32 = 100;

/// Caller-supplied arguments. `deny_unknown_fields` is the security
/// guarantee behind the scoping promise in the module doc: an agent cannot
/// smuggle a `user` field through JSON-RPC to override the server-side
/// identity. Any unknown key is rejected with `invalid_params` before this
/// code runs.
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

/// `effective = min(caller.unwrap_or(DEFAULT), GATEWAY_ROW_LIMIT_CEILING)`.
/// Same most-restrictive-wins posture as `target::effective_row_limit`,
/// minus the grant column: history is read-only against audit data, no
/// `row_limit` constraint applies. The ceiling is what bounds a hostile
/// caller from asking for `u32::MAX` rows and getting back the entire audit
/// table slice they happen to be entitled to.
pub(super) fn effective_limit(caller: Option<u32>) -> u32 {
    caller
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .min(GATEWAY_ROW_LIMIT_CEILING)
}

/// Whether `effective_limit` lowered what the caller asked for.
///
/// Split out from the response assembly so the distinction it encodes is
/// testable: this is a *clamp* signal, not a "there is more data" signal.
/// Conflating the two is easy to do by accident and would tell an agent to
/// keep raising `limit` against a ceiling that will never yield more.
pub(super) fn limit_was_clamped(caller: Option<u32>, effective: u32) -> bool {
    caller.is_some_and(|asked| asked > effective)
}

/// Build an `Outcome` for a post-deserialisation argument rejection.
///
/// The wire response keeps the JSON-RPC `invalid_params` envelope (-32602)
/// — this is a structural, transport-layer error, not a tool result — while
/// the audit row records `outcome = "invalid_arguments"` so a caller
/// probing the boundary with `limit: 0` or a malformed `since` still leaves
/// a trail. `error_outcome` is the wrong shape here: it wraps the response
/// as a `tool_error` (`isError: true` inside the tool result), which would
/// change the wire contract for callers already relying on the JSON-RPC
/// error envelope (see `history_rejects_smuggled_user_field`).
pub(super) fn invalid_arguments_outcome(id: Value, message: &str) -> Outcome {
    Outcome {
        response: Response::error(id, ErrorObject::invalid_params(message)),
        code: OutcomeCode::InvalidArguments,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: Some(message.to_string()),
    }
}

/// Parse an RFC 3339 timestamp at the edge. Any failure becomes a typed
/// `invalid_params` so a malformed `since` doesn't silently mean "no filter"
/// (which would let a caller pull history beyond their intended window).
pub(super) fn parse_since(value: Option<&str>) -> Result<Option<DateTime<Utc>>, ()> {
    let Some(raw) = value else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|_| ())
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
