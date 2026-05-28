//! The single chokepoint every tool dispatch flows through: refuses if the
//! state DB is missing (audit unavailable), runs the tool's `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).
//!
//! Extracted from the original `run_query` so each new tool (`list_databases`,
//! `describe_schema`, `sample_table`, …) gets the same guarantees without
//! re-implementing the chokepoint.

use std::future::Future;

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
    /// `syntax_error`, `unavailable`, `reason_required`, `internal`).
    pub code: &'static str,
    pub elapsed_ms: Option<i64>,
}

/// Audit context known up-front from the tool's arguments — before any work
/// runs. `server`/`database` are `Some` for per-DB tools; `sql` is `Some` for
/// query tools (`run_query`, `sample_table`'s generated SQL).
pub struct AuditHeader<'a> {
    pub tool: &'static str,
    pub server: Option<&'a str>,
    pub database: Option<&'a str>,
    pub sql: Option<&'a str>,
}

pub async fn audit_dispatch<Fut>(
    id: Value,
    identity: &Identity,
    state_db: Option<&PgPool>,
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
        tool: header.tool.to_string(),
        server: header.server.map(str::to_string),
        database: header.database.map(str::to_string),
        sql: header.sql.map(str::to_string),
        outcome: outcome.code.to_string(),
        elapsed_ms: outcome.elapsed_ms,
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
}
