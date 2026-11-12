use std::time::Instant;

use serde_json::Value;
use uuid::Uuid;

use crate::exec::{ExecError, RejectionKind};
use crate::mcp::jsonrpc::{ErrorObject, Response};
use crate::mcp::protocol::{CallToolResult, TextContent};

use super::{Outcome, OutcomeCode, Reply};

/// Build a structured tool error response per spec 03 §Errors. The body's
/// `request_id` is the gateway UUID — the value in `audit_calls.request_id`
/// and the `x-request-id` header — so the id an agent pastes back to ops
/// finds the row. `id` is the client's JSON-RPC id, echoed in the envelope
/// only. Called only by the chokepoint, the one place that knows both.
pub(super) fn tool_error(
    id: Value,
    request_id: Uuid,
    code: OutcomeCode,
    message: &str,
) -> Response {
    let body = serde_json::json!({
        "request_id": request_id.to_string(),
        "code": code.as_str(),
        "message": message,
    });
    Response::result(
        id,
        &CallToolResult {
            content: vec![TextContent::new(body.to_string())],
            is_error: true,
        },
    )
}

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
        ExecError::Sql => (OutcomeCode::SyntaxError, messages.sql_rejected),
        // Every DB rejection carries the SQLSTATE and the server's primary
        // message (role already redacted by exec) so the agent can act on it;
        // two SQLSTATEs get their own codes.
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
        ExecError::PasswordUnresolved { .. }
        | ExecError::UnsupportedAdapter(_)
        | ExecError::NotImplemented { .. } => {
            (OutcomeCode::Internal, "server-side configuration error")
        }
    };
    let mut outcome = error_outcome(code, message);
    outcome.elapsed_ms = Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX));
    outcome
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
mod tests {
    use super::*;

    #[test]
    fn tool_error_payload_shape() {
        let request_id = Uuid::new_v4();
        let response = tool_error(Value::from(7), request_id, OutcomeCode::Forbidden, "nope");
        let value = serde_json::to_value(&response).unwrap();
        // The client's JSON-RPC id stays in the envelope only…
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["isError"], true);
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["message"], "nope");
        // …the body carries the gateway id that keys the audit row.
        assert_eq!(body["request_id"], request_id.to_string());
    }

    #[test]
    fn tool_success_payload_shape() {
        let response = tool_success(Value::from(1), r#"{"hello":"world"}"#.to_string());
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["isError"], false);
        assert_eq!(
            value["result"]["content"][0]["text"],
            r#"{"hello":"world"}"#
        );
    }

    #[test]
    fn error_outcome_mirrors_message_into_audit() {
        let outcome = error_outcome(OutcomeCode::Forbidden, "no grants");
        assert_eq!(outcome.code, OutcomeCode::Forbidden);
        assert_eq!(outcome.error_message.as_deref(), Some("no grants"));
        assert!(outcome.row_count.is_none());
    }

    /// Defense-in-depth backstop: an undispatchable `kind` is now rejected at
    /// boot (`config::yaml` validation), so a validated config never reaches
    /// `UnsupportedAdapter`. If an internal caller ever does, the tool must
    /// still map it to the stable `internal` code with a generic message —
    /// never the raw `ServerKind` debug, which could hint at backend topology.
    #[test]
    fn unsupported_adapter_maps_to_internal_without_leaking_kind() {
        use crate::config::ServerKind;

        let messages = ToolErrorMessages {
            timeout: "t",
            sql_rejected: "s",
            forbidden_prefix: "query",
        };
        let outcome = outcome_from_exec_error(
            ExecError::UnsupportedAdapter(ServerKind::Mysql),
            Instant::now(),
            &messages,
        );
        assert_eq!(outcome.code, OutcomeCode::Internal);
        assert_eq!(
            outcome.error_message.as_deref(),
            Some("server-side configuration error")
        );
        // The backend identity must not ride along into the client-facing text.
        let msg = outcome.error_message.unwrap_or_default().to_lowercase();
        assert!(!msg.contains("mysql"), "{msg}");
    }

    #[test]
    fn invalid_arguments_uses_the_invalid_params_envelope() {
        let outcome = invalid_arguments(Value::from(3), "`limit` must be at least 1");
        assert_eq!(outcome.code, OutcomeCode::InvalidArguments);
        let Reply::Response(response) = &outcome.reply else {
            panic!("invalid arguments keep the JSON-RPC envelope");
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["error"]["code"], -32602);
        assert_eq!(
            outcome.error_message.as_deref(),
            Some("`limit` must be at least 1")
        );
    }

    #[test]
    fn success_outcome_carries_row_metadata() {
        let outcome = success_outcome(
            Value::from(1),
            "{}".to_string(),
            Some(42),
            Some(100),
            Some(true),
        );
        assert_eq!(outcome.code, OutcomeCode::Success);
        assert_eq!(outcome.elapsed_ms, Some(42));
        assert_eq!(outcome.row_count, Some(100));
        assert_eq!(outcome.truncated, Some(true));
        assert!(outcome.error_message.is_none());
    }
}
