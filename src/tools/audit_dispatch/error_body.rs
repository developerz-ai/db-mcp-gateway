//! The spec 03 tool error body: what went wrong (`code`, `message`), and
//! what the agent can do next (`retryable`, `hint`, `limit`), and where in
//! the statement it went wrong (`position`, `db_hint`, `near_misses`,
//! `location`).

use serde_json::Value;
use uuid::Uuid;

use crate::mcp::jsonrpc::Response;
use crate::mcp::protocol::{CallToolResult, TextContent};

use crate::exec::sql_guard::SqlLocation;

use super::types::RejectionDetail;
use super::{HitLimit, OutcomeCode, Reply, WriteState};

/// Everything in a tool error body but the `request_id`, which only the
/// chokepoint knows.
#[derive(Debug, Clone, Copy)]
pub(super) struct ToolErrorBody<'a> {
    pub code: OutcomeCode,
    pub message: &'a str,
    /// Set for a call that ran with write access, and only then in the body.
    pub write: Option<WriteState>,
    pub elapsed_ms: Option<i64>,
    pub detail: ErrorDetail<'a>,
}

/// The one optional block a tool error body carries beyond the common fields.
#[derive(Debug, Clone, Copy, Default)]
pub(super) enum ErrorDetail<'a> {
    #[default]
    None,
    Limit(HitLimit),
    Rejection(&'a RejectionDetail),
    Location(SqlLocation),
}

impl<'a> ErrorDetail<'a> {
    pub(super) fn of(reply: &'a Reply) -> Self {
        match reply {
            Reply::Response(_) | Reply::ToolError => Self::None,
            Reply::LimitHit(limit) => Self::Limit(*limit),
            Reply::Rejected(rejection) => Self::Rejection(rejection),
            Reply::Unparsed(location) => Self::Location(*location),
        }
    }
}

/// Build a structured tool error response per spec 03 §Errors. The body's
/// `request_id` is the gateway UUID — the value in `audit_calls.request_id`
/// and the `x-request-id` header — so the id an agent pastes back to ops
/// finds the row. `id` is the client's JSON-RPC id, echoed in the envelope
/// only. Called only by the chokepoint, the one place that knows both.
pub(super) fn tool_error(id: Value, request_id: Uuid, body: ToolErrorBody<'_>) -> Response {
    let mut wire = serde_json::json!({
        "request_id": request_id.to_string(),
        "code": body.code.as_str(),
        "message": body.message,
        "retryable": retryable(body.code, body.write),
        "hint": hint(body.code),
    });
    if let Some(write) = body.write {
        wire["write"] = serde_json::json!(write);
    }
    if let Some(elapsed_ms) = body.elapsed_ms {
        wire["elapsed_ms"] = serde_json::json!(elapsed_ms);
    }
    match body.detail {
        ErrorDetail::None => {}
        ErrorDetail::Limit(limit) => wire["limit"] = serde_json::json!(limit),
        ErrorDetail::Location(location) => wire["location"] = serde_json::json!(location),
        ErrorDetail::Rejection(rejection) => {
            if let Some(position) = rejection.position {
                wire["position"] = serde_json::json!(position);
            }
            if let Some(db_hint) = &rejection.db_hint {
                wire["db_hint"] = serde_json::json!(db_hint);
            }
            if !rejection.near_misses.is_empty() {
                wire["near_misses"] = serde_json::json!(rejection.near_misses);
            }
        }
    }
    Response::result(
        id,
        &CallToolResult {
            content: vec![TextContent::new(wire.to_string())],
            is_error: true,
        },
    )
}

/// Whether the same call, unchanged, may succeed if sent again: only for a
/// fault in the path to the data, never the call itself — and never when a
/// write may already be in the target, where a retry could write twice.
fn retryable(code: OutcomeCode, write: Option<WriteState>) -> bool {
    if matches!(write, Some(WriteState::Applied | WriteState::Unknown)) {
        return false;
    }
    matches!(
        code,
        OutcomeCode::Unavailable | OutcomeCode::AuditUnavailable | OutcomeCode::Cancelled
    )
}

/// The next step for each code, short enough to act on without the spec.
fn hint(code: OutcomeCode) -> &'static str {
    match code {
        OutcomeCode::Forbidden => {
            "see list_servers / list_databases for the servers and databases you can use"
        }
        OutcomeCode::ForbiddenSql => {
            "send one statement your grant covers (read-only unless it grants query_write)"
        }
        OutcomeCode::PermissionDenied => {
            "the database role cannot do this; pick an object describe_schema lists"
        }
        OutcomeCode::UndefinedObject => "check the table and column names with describe_schema",
        OutcomeCode::InvalidArguments => "fix the named argument and call again",
        OutcomeCode::ReasonRequired => "ask the user why, and call again with `reason`",
        OutcomeCode::Timeout => {
            "narrow the query (filter, LIMIT, indexed columns); check its plan with explain"
        }
        OutcomeCode::SyntaxError => {
            "fix the statement and call again; describe_schema lists the real names"
        }
        OutcomeCode::Unavailable | OutcomeCode::AuditUnavailable => {
            "transient: call again after a short backoff"
        }
        OutcomeCode::UnsupportedBackend => {
            "this tool is not offered on this server's kind; use run_query"
        }
        OutcomeCode::Cancelled => "cancel_query stopped this call; call again if still needed",
        OutcomeCode::Internal | OutcomeCode::Abandoned => {
            "a gateway fault: report the request_id to the gateway operator"
        }
        OutcomeCode::Success | OutcomeCode::DryRun => "",
    }
}

#[cfg(test)]
#[path = "error_body_tests.rs"]
mod tests;
