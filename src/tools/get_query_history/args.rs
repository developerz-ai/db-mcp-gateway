//! Argument contract for `get_query_history`: the deserialised shape and the
//! post-deserialisation checks (`since`, `limit`) applied once at the edge.

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// Hard floor on entries returned when no caller `limit` is supplied.
/// History is "recover context across sessions", not "bulk export" — small
/// by default keeps the response bounded and the agent's recovery loop
/// cheap.
const DEFAULT_HISTORY_LIMIT: u32 = 100;

/// Most entries one page returns. Older entries are reached through
/// `cursor`, never through a bigger page.
pub(super) const HISTORY_LIMIT_CEILING: u32 = 1000;

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
    /// `next_cursor` from the previous page; absent for the newest page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Required when the grant sets `require_reason`; recorded in the audit
    /// row either way.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `effective = min(caller.unwrap_or(DEFAULT), HISTORY_LIMIT_CEILING)`.
/// History is read-only against audit data, so no grant `row_limit`
/// applies; the ceiling is what bounds a hostile caller asking for
/// `u32::MAX` rows of the audit table slice they are entitled to.
pub(super) fn effective_limit(caller: Option<u32>) -> u32 {
    caller
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .min(HISTORY_LIMIT_CEILING)
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
