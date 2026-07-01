//! Shared data types for the audit-dispatch chokepoint.

use std::net::{IpAddr, SocketAddr};

use crate::transport::jsonrpc::Response;

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
