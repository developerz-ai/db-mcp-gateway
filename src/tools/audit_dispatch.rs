//! The single chokepoint every tool dispatch flows through: refuses if the
//! state DB is missing (audit unavailable), runs the tool's `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).
//!
//! Extracted from the original `run_query` so each tool gets the same
//! guarantees without re-implementing the chokepoint.

use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;

use serde_json::Value;
use sqlx::PgPool;

use crate::audit::{self, AuditRow};
use crate::auth::Identity;
use crate::transport::jsonrpc::{ErrorObject, Response};
use crate::transport::protocol::{CallToolResult, TextContent};

/// Result of a tool's compute step. Carries the response to send back AND
/// the audit fields the helper will persist.
pub struct Outcome {
    pub response: Response,
    /// `"success"` or a spec 03 error code (`forbidden`, `timeout`,
    /// `syntax_error`, `unavailable`, `reason_required`, `internal`,
    /// `forbidden_sql`).
    pub code: &'static str,
    pub elapsed_ms: Option<i64>,
    /// Rows returned to the agent (after any truncation). `None` for tools
    /// that don't return rows.
    pub row_count: Option<i64>,
    /// `Some(true)` if the row cap clipped the result; `None` for tools
    /// that don't have a row cap.
    pub truncated: Option<bool>,
    /// User-facing error message we surfaced; mirrored to the audit row.
    /// `None` on success. MUST be the typed string we sent, never a raw
    /// DB error.
    pub error_message: Option<String>,
}

/// Audit context known up-front from the tool's arguments — before any work
/// runs. `server`/`database` are `Some` for per-DB tools; `sql` is `Some` for
/// query tools (`run_query`, `sample_table`'s generated SQL).
pub struct AuditHeader<'a> {
    pub tool: &'static str,
    pub server: Option<&'a str>,
    pub database: Option<&'a str>,
    pub sql: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// Per-request context the transport layer captures (IP, agent client).
/// Threaded through `dispatch_call` so every tool's audit row gets the same
/// view of the request, with no per-tool plumbing.
#[derive(Debug, Default, Clone)]
pub struct RequestContext {
    pub ip: Option<IpAddr>,
    pub agent_client: Option<String>,
}

impl RequestContext {
    /// Build from an axum `ConnectInfo<SocketAddr>` + an optional User-Agent
    /// header. Both are best-effort; missing values just stay `None`.
    pub fn from_request(addr: Option<SocketAddr>, user_agent: Option<&str>) -> Self {
        Self {
            ip: addr.map(|a| a.ip()),
            agent_client: user_agent.map(str::to_string),
        }
    }
}

pub async fn audit_dispatch<Fut>(
    id: Value,
    identity: &Identity,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    header: AuditHeader<'_>,
    work: Fut,
) -> Response
where
    Fut: Future<Output = Outcome>,
{
    let Some(state_db) = state_db else {
        return Response::error(
            id,
            ErrorObject::internal(format!(
                "audit log unavailable — refusing to dispatch {}",
                header.tool
            )),
        );
    };

    let outcome = work.await;

    let row = AuditRow {
        request_id: id.to_string(),
        user_sub: identity.user_sub.clone(),
        user_email: identity.user_email.clone(),
        groups: identity.groups.clone(),
        tool: header.tool.to_string(),
        server: header.server.map(str::to_string),
        database: header.database.map(str::to_string),
        sql: header.sql.map(str::to_string),
        reason: header.reason.map(str::to_string),
        outcome: outcome.code.to_string(),
        elapsed_ms: outcome.elapsed_ms,
        row_count: outcome.row_count,
        truncated: outcome.truncated,
        error_message: outcome.error_message,
        agent_client: request_ctx.agent_client.clone(),
        ip: request_ctx.ip.map(|i| i.to_string()),
    };
    if let Err(err) = audit::log(state_db, &row).await {
        // Don't embed the underlying error string in the response (could leak
        // DB connection details on some sqlx error paths). Operator sees the
        // chained source via the tracing event.
        tracing::error!(
            %err,
            request_id = %id,
            tool = %header.tool,
            "audit write failed; aborting tool response"
        );
        return Response::error(
            id,
            ErrorObject::internal("audit write failed; request rejected"),
        );
    }

    outcome.response
}

/// Build a structured tool error response per spec 03 §Errors. `request_id`
/// is duplicated inside the JSON body so agents that only read the tool
/// payload still get it.
pub fn tool_error(id: Value, code: &'static str, message: &str) -> Response {
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
pub fn error_outcome(id: Value, code: &'static str, message: &str) -> Outcome {
    Outcome {
        response: tool_error(id, code, message),
        code,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: Some(message.to_string()),
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
