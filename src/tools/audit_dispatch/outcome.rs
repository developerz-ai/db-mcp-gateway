use std::time::Instant;

use serde_json::Value;

use crate::audit::intent::WRITE_MAY_HAVE_COMMITTED;
use crate::exec::adapter::effective_timeout_ms;
use crate::exec::sql_guard::GuardError;
use crate::exec::{DbRejection, ExecError, ExecResult, RejectionKind};
use crate::mcp::jsonrpc::{ErrorObject, Response};
use crate::mcp::protocol::{CallToolResult, TextContent};

use super::types::RejectionDetail;
use super::{HitLimit, Outcome, OutcomeCode, Reply, WriteState};

/// Build a successful tool result from a JSON-serialised payload string.
pub fn tool_success(id: Value, text: String) -> Response {
    Response::result(
        id,
        &CallToolResult {
            content: vec![TextContent::new(text)],
            is_error: false,
        },
    )
}

/// Shortcut for the common error-outcome shape: a spec 03 tool error the
/// chokepoint renders, with the message mirrored into `error_message` (it is
/// both the client text and the audit row's).
///
/// Scoped to `crate::tools`: the tools own their per-tool wording. Anything
/// outside must route target-DB errors through [`outcome_from_exec_error`].
pub(in crate::tools) fn error_outcome(code: OutcomeCode, message: &str) -> Outcome {
    Outcome {
        reply: Reply::ToolError,
        code,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: Some(message.to_string()),
        write: None,
    }
}

/// A rejected argument (spec 03 §Errors `invalid_arguments`): the wire keeps
/// the JSON-RPC `invalid_params` (-32602) envelope — a structural error, not
/// a tool result — while the audit row records `invalid_arguments`, so a
/// caller probing the argument boundary still leaves a trail.
pub(in crate::tools) fn invalid_arguments(id: Value, message: &str) -> Outcome {
    Outcome {
        reply: Reply::Response(Box::new(Response::error(
            id,
            ErrorObject::invalid_params(message),
        ))),
        code: OutcomeCode::InvalidArguments,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: Some(message.to_string()),
        write: None,
    }
}

/// Per-tool wording for the user-facing strings inside
/// [`outcome_from_exec_error`]. Each tool defines a const of these so the
/// shared mapping can stay one function while error messages keep their
/// tool-specific shape. Spec 03 error *codes* are NOT configurable here —
/// they're fixed by the shared mapping below.
#[derive(Debug)]
pub struct ToolErrorMessages {
    /// Message for `ExecError::Timeout`. Per-tool because EXPLAIN says
    /// "EXPLAIN exceeded …" while `run_query` says "query exceeded …".
    pub timeout: &'static str,
    /// Message for `ExecError::Sql`. Per-tool because `describe_schema`
    /// surfaces "catalog query was rejected" while `run_query` says
    /// "the target DB rejected the SQL".
    pub sql_rejected: &'static str,
    /// Prefix for `ExecError::Forbidden(reason)`. The final message is
    /// `"<prefix> rejected by gateway: <reason>"`. Per-tool because the
    /// noun changes: "query" / "EXPLAIN" / "sample" / "catalog query".
    pub forbidden_prefix: &'static str,
}

/// Map an `ExecError` to the spec 03 outcome code + a user-facing message,
/// then build the matching `Outcome` with `elapsed_ms` filled from the
/// `started` wall clock so error paths still carry duration into the
/// audit row.
///
/// The four tool-specific call sites used to duplicate this match in 5
/// arms × 4 files = 20 arms total; adding `ExecError::NotImplemented` in
/// #57 made that pain visible. Per-tool wording rides in
/// [`ToolErrorMessages`] so the shared mapping stays one function.
pub fn outcome_from_exec_error(
    err: ExecError,
    started: Instant,
    messages: &ToolErrorMessages,
) -> Outcome {
    let detail = match &err {
        ExecError::Rejected(rejection) => Some(rejection_detail(rejection)),
        _ => None,
    };
    let owned;
    let (code, message): (OutcomeCode, &str) = match err {
        ExecError::Timeout => (OutcomeCode::Timeout, messages.timeout),
        // Another call of the same identity cancelled this one (`cancel_query`).
        ExecError::Cancelled => (
            OutcomeCode::Cancelled,
            "query was cancelled by cancel_query",
        ),
        ExecError::Connection | ExecError::Unavailable => {
            (OutcomeCode::Unavailable, "target database is unreachable")
        }
        // Only a write's commit yields this, so the write note always applies.
        ExecError::CommitIndeterminate => {
            owned = format!(
                "connection lost during commit; the write may or may not have been applied \
                 ({WRITE_MAY_HAVE_COMMITTED})"
            );
            (OutcomeCode::Unavailable, owned.as_str())
        }
        ExecError::Sql => (OutcomeCode::SyntaxError, messages.sql_rejected),
        // Every DB rejection carries the SQLSTATE and gateway wording (exec
        // names at most the identifier at the parser's error position) so the
        // agent can act on it; two SQLSTATEs get their own codes.
        ExecError::Rejected(rejection) => match rejection.kind() {
            RejectionKind::PermissionDenied => {
                owned = rejection.to_string();
                (OutcomeCode::PermissionDenied, owned.as_str())
            }
            RejectionKind::UndefinedObject => {
                owned = rejection.to_string();
                (OutcomeCode::UndefinedObject, owned.as_str())
            }
            RejectionKind::Other => {
                owned = format!("{}: {rejection}", messages.sql_rejected);
                (OutcomeCode::SyntaxError, owned.as_str())
            }
        },
        ExecError::Decode => (
            OutcomeCode::Internal,
            "target returned a value the gateway could not decode",
        ),
        ExecError::Forbidden(reason) => {
            owned = format!(
                "{prefix} rejected by gateway: {reason}",
                prefix = messages.forbidden_prefix,
            );
            (OutcomeCode::ForbiddenSql, owned.as_str())
        }
        // Boot validation refuses a `query_write` grant without a write role,
        // so this is a write the configuration does not allow.
        ExecError::WriteNotConfigured => (
            OutcomeCode::Forbidden,
            "this database accepts no writes through the gateway",
        ),
        // A tool the target's engine does not offer: a stable answer, not a bug.
        ExecError::NotImplemented { .. } => (
            OutcomeCode::UnsupportedBackend,
            "this tool is not supported on this database's backend",
        ),
        ExecError::PasswordUnresolved { .. } | ExecError::UnsupportedAdapter(_) => {
            (OutcomeCode::Internal, "server-side configuration error")
        }
    };
    let mut outcome = error_outcome(code, message);
    outcome.elapsed_ms = Some(elapsed_ms_since(started));
    if let Some(detail) = detail {
        outcome.reply = Reply::Rejected(Box::new(detail));
    }
    outcome
}

fn rejection_detail(rejection: &DbRejection) -> RejectionDetail {
    RejectionDetail {
        position: rejection.position(),
        db_hint: rejection.hint().map(str::to_owned),
        near_misses: rejection.near_misses().to_vec(),
    }
}

/// A statement the SQL guard refused: `forbidden_sql`, with the body's
/// `location` when the parser said where it stopped.
pub(in crate::tools) fn guard_rejected(err: &GuardError) -> Outcome {
    let mut outcome = error_outcome(
        OutcomeCode::ForbiddenSql,
        &format!("SQL rejected by gateway: {err}"),
    );
    if let Some(location) = err.location() {
        outcome.reply = Reply::Unparsed(location);
    }
    outcome
}

/// A `timeout` outcome names the budget it ran out of — in the message and
/// as the body's `limit` — and points at `explain`, so the agent's next call
/// can be a narrower query rather than the same one. `grant_timeout_ms` is
/// the merged grant's `statement_timeout_ms`; the budget the adapter applied
/// is that clamped to the gateway ceiling. Any other outcome is untouched.
pub(in crate::tools) fn note_timeout_limit(outcome: &mut Outcome, grant_timeout_ms: Option<u32>) {
    if outcome.code != OutcomeCode::Timeout {
        return;
    }
    let budget_ms = effective_timeout_ms(grant_timeout_ms);
    if let Some(message) = outcome.error_message.as_mut() {
        message.push_str(&format!(
            " ({budget_ms} ms); check the plan with explain, or narrow the query"
        ));
    }
    outcome.reply = Reply::LimitHit(HitLimit {
        name: "statement_timeout_ms",
        value: u64::from(budget_ms),
    });
}

/// Milliseconds since `started`, as the audit row's `elapsed_ms` stores them.
pub(in crate::tools) fn elapsed_ms_since(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Whether a write's change is in the target, from how its execution ended.
/// Only a statement cut off at or after the commit can have landed unseen:
/// every other failure is raised before the commit and rolls back.
pub(in crate::tools) fn write_state(
    executed: &Result<ExecResult, ExecError>,
    dry_run: bool,
) -> WriteState {
    match executed {
        _ if dry_run => WriteState::NotApplied,
        Ok(_) => WriteState::Applied,
        Err(ExecError::Timeout | ExecError::Cancelled | ExecError::CommitIndeterminate) => {
            WriteState::Unknown
        }
        Err(_) => WriteState::NotApplied,
    }
}

/// Shortcut for the success shape with row/truncation metadata.
pub fn success_outcome(
    id: Value,
    text: String,
    elapsed_ms: Option<i64>,
    row_count: Option<i64>,
    truncated: Option<bool>,
) -> Outcome {
    Outcome {
        reply: Reply::Response(Box::new(tool_success(id, text))),
        code: OutcomeCode::Success,
        elapsed_ms,
        row_count,
        truncated,
        error_message: None,
        write: None,
    }
}

#[cfg(test)]
#[path = "outcome_tests.rs"]
mod tests;
