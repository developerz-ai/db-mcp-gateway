use std::time::Instant;

use serde_json::Value;

use crate::exec::ExecError;
use crate::transport::jsonrpc::Response;
use crate::transport::protocol::{CallToolResult, TextContent};

use super::Outcome;

/// Build a structured tool error response per spec 03 §Errors. `request_id`
/// is duplicated inside the JSON body so agents that only read the tool
/// payload still get it.
///
/// Exposed to `super` (`audit_dispatch::mod`) so audit-write failures can
/// surface the spec-03 code (`"timeout"` / `"internal"`) instead of a bare
/// JSON-RPC internal error. External tool callers keep using
/// `error_outcome` / `outcome_from_exec_error`.
pub(super) fn tool_error(id: Value, code: &'static str, message: &str) -> Response {
    let body = serde_json::json!({
        "request_id": id.clone(),
        "code": code,
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

/// Shortcut for the common error-outcome shape: a typed tool_error response
/// plus the matching audit fields (the message is mirrored into
/// `error_message` so operators can read it from the audit row).
///
/// Scoped to `crate::tools`: the tools own their per-tool wording. Anything
/// outside must route target-DB errors through [`outcome_from_exec_error`].
pub(in crate::tools) fn error_outcome(id: Value, code: &'static str, message: &str) -> Outcome {
    Outcome {
        response: tool_error(id, code, message),
        code,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: Some(message.to_string()),
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
    id: Value,
    err: ExecError,
    started: Instant,
    messages: &ToolErrorMessages,
) -> Outcome {
    let owned;
    let (code, message): (&str, &str) = match err {
        ExecError::Timeout => ("timeout", messages.timeout),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", messages.sql_rejected),
        ExecError::Forbidden(reason) => {
            owned = format!(
                "{prefix} rejected by gateway: {reason}",
                prefix = messages.forbidden_prefix,
            );
            ("forbidden_sql", owned.as_str())
        }
        ExecError::PasswordUnresolved { .. }
        | ExecError::UnsupportedAdapter(_)
        | ExecError::NotImplemented { .. } => ("internal", "server-side configuration error"),
    };
    let mut outcome = error_outcome(id, code, message);
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
        response: tool_success(id, text),
        code: "success",
        elapsed_ms,
        row_count,
        truncated,
        error_message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_payload_shape() {
        let response = tool_error(Value::from(7), "forbidden", "nope");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["isError"], true);
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["message"], "nope");
        assert_eq!(body["request_id"], 7);
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
        let outcome = error_outcome(Value::from(1), "forbidden", "no grants");
        assert_eq!(outcome.code, "forbidden");
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
            Value::from(1),
            ExecError::UnsupportedAdapter(ServerKind::Mysql),
            Instant::now(),
            &messages,
        );
        assert_eq!(outcome.code, "internal");
        assert_eq!(
            outcome.error_message.as_deref(),
            Some("server-side configuration error")
        );
        // The backend identity must not ride along into the client-facing text.
        let msg = outcome.error_message.unwrap_or_default().to_lowercase();
        assert!(!msg.contains("mysql"), "{msg}");
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
        assert_eq!(outcome.code, "success");
        assert_eq!(outcome.elapsed_ms, Some(42));
        assert_eq!(outcome.row_count, Some(100));
        assert_eq!(outcome.truncated, Some(true));
        assert!(outcome.error_message.is_none());
    }
}
