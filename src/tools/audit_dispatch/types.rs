//! Shared data types for the audit-dispatch chokepoint.

use std::net::{IpAddr, SocketAddr};

use uuid::Uuid;

use crate::transport::jsonrpc::Response;

/// Result of a tool's compute step. Carries the response to send back AND
/// the audit fields the helper will persist.
#[derive(Debug)]
pub struct Outcome {
    pub response: Response,
    /// `"success"` or a spec 03 error code (`forbidden`, `forbidden_sql`,
    /// `invalid_arguments`, `reason_required`, `timeout`, `syntax_error`,
    /// `unavailable`, `internal`).
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

/// Per-request context the transport layer captures (IP, agent client).
/// Threaded through `dispatch_call` so every tool's audit row gets the same
/// view of the request, with no per-tool plumbing.
#[derive(Debug, Default, Clone)]
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
    /// always correlate through one canonical, well-formed value. Defaults
    /// to the nil UUID via `#[derive(Default)]` — fine for tests that don't
    /// care about it; every production request goes through
    /// [`Self::from_request`], which always mints a fresh one.
    pub request_id: Uuid,
}

impl RequestContext {
    /// Build from an axum `ConnectInfo<SocketAddr>` + an optional User-Agent
    /// header. Both are best-effort; missing values just stay `None`. Mints
    /// a fresh `request_id` — see the field doc for why this, not the
    /// client's JSON-RPC id, is the correlation value.
    pub fn from_request(addr: Option<SocketAddr>, user_agent: Option<&str>) -> Self {
        Self {
            ip: addr.map(|a| a.ip()),
            agent_client: user_agent.map(str::to_string),
            request_id: Uuid::new_v4(),
        }
    }
}
