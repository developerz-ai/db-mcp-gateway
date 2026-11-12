//! Shared data types for the audit-dispatch chokepoint.

use std::net::IpAddr;

use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::OutcomeCode;
use crate::audit::drain::DetachedTasks;
use crate::audit::stream::StreamSinks;
use crate::mcp::jsonrpc::Response;

/// What goes back to the client for one dispatch.
#[derive(Debug)]
pub enum Reply {
    /// A finished response (a tool result, or a JSON-RPC error envelope).
    /// Boxed: a `Response` dwarfs the unit `ToolError` variant.
    Response(Box<Response>),
    /// A spec 03 tool error. Rendered by the chokepoint from the outcome's
    /// `code` and `error_message`, because only it knows the gateway
    /// `request_id` the error body carries.
    ToolError,
}

/// Result of a tool's compute step. Carries the reply to send back AND
/// the audit fields the helper will persist.
#[derive(Debug)]
pub struct Outcome {
    pub reply: Reply,
    /// Stringified once, into the audit row, by the chokepoint.
    pub code: OutcomeCode,
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
/// runs. `server`/`database` are `Some` for per-DB tools whose arguments
/// parsed; `sql` is what the call reads — the agent's SQL for `run_query` /
/// `explain`, the target `schema.table` for `sample_table` /
/// `describe_schema`.
#[derive(Debug, Clone, Copy)]
pub struct AuditHeader<'a> {
    pub tool: &'static str,
    pub server: Option<&'a str>,
    pub database: Option<&'a str>,
    pub sql: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// Backend kind — `"postgres"` / `"mongo"` — derived from `server.kind`.
    /// `None` for tools that don't dispatch to a target DB (`list_servers`).
    /// Spec 12 line 241 / #58 acceptance.
    pub db_type: Option<&'a str>,
}

impl AuditHeader<'_> {
    /// A header for a call whose arguments never parsed: no target, nothing
    /// read.
    pub fn untargeted(tool: &'static str) -> Self {
        Self {
            tool,
            server: None,
            database: None,
            sql: None,
            reason: None,
            db_type: None,
        }
    }
}

/// Where a dispatch's audit rows go: the state DB, the stream sinks fed
/// after each durable write, and the tracked set the drop-guard's fallback
/// write runs on.
#[derive(Debug, Clone, Copy)]
pub struct AuditStore<'a> {
    pub pool: &'a PgPool,
    pub sinks: &'a StreamSinks,
    pub tasks: &'a DetachedTasks,
}

/// Per-request context the transport layer captures (IP, agent client).
/// Threaded through `dispatch_call` so every tool's audit row gets the same
/// view of the request, with no per-tool plumbing.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip: Option<IpAddr>,
    pub agent_client: Option<String>,
    /// Gateway-minted correlation id for this dispatch — NOT the client's
    /// JSON-RPC `id`. That value is caller-controlled (arbitrary JSON: a
    /// number, a string with embedded quotes, unbounded length, or the same
    /// value reused across every call a buggy/malicious client makes) and is
    /// only ever echoed back in the JSON-RPC response envelope, never
    /// persisted. `request_id` is what both the `tool_dispatch` tracing span
    /// and `audit_calls.request_id` use, so a log line and its audit row
    /// always correlate through one canonical, well-formed value. No
    /// `Default`: a shared nil id would collide on `audit_call_intents`'
    /// primary key, so every caller supplies a fresh one.
    pub request_id: Uuid,
}
