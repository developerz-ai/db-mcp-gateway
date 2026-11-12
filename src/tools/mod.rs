//! MCP tool implementations.
//!
//! Each tool is a handler with shape `run(ctx, id, args) -> jsonrpc::Response`.
//! The transport routes `tools/call` to `dispatch_call`, which fans out by
//! tool name.
//!
//! Security-required (see CLAUDE.md). Every tool that returns config data
//! MUST go through a credential-free view type (see `SafeServerView`); never
//! serialize a `crate::config::Server` to the wire.

pub mod audit_dispatch;
mod context;
pub mod describe_schema;
pub mod explain;
pub mod get_query_history;
pub mod list_databases;
pub mod list_servers;
pub mod run_query;
pub mod sample_table;
mod target;

use serde::Deserialize;
use serde_json::Value;
use tracing::Instrument;
use tracing::info_span;

use crate::audit::prefix_at_char_boundary;
use crate::config::{ConfigFile, ServerKind};
use crate::mcp::jsonrpc::Response;

/// Map a `ServerKind` to its audit-row string. Single source of truth so
/// audit rows + the [`list_servers`] tool view never disagree about the
/// label. Returned strings match the `audit_calls.db_type` values written
/// in migration 0007.
pub(crate) fn db_type_label(kind: ServerKind) -> &'static str {
    match kind {
        ServerKind::Postgres => "postgres",
        ServerKind::Mysql => "mysql",
        ServerKind::Mssql => "mssql",
        ServerKind::Mongo => "mongo",
    }
}

/// Look up the `db_type` label for a server by name. `None` when the
/// server doesn't exist in config — caller's authz check will surface that
/// downstream. Used in the per-DB tools' `AuditHeader` construction so the
/// cancel-path audit row has the right `db_type` even when the work is
/// dropped before `compute_outcome` runs.
pub(crate) fn db_type_for_server(config: &ConfigFile, server_name: &str) -> Option<&'static str> {
    config
        .servers
        .iter()
        .find(|s| s.name == server_name)
        .map(|s| db_type_label(s.kind))
}

/// Gateway-wide ceiling on rows returned in a single response, regardless of
/// what the caller's `limit` argument requests or whether the grant sets its
/// own `row_limit` constraint. Spec 03 §4 "Results are size-capped ... the
/// gateway clamps it to a per-database max" — a grant that declines to set
/// `row_limit` must still mean *a* max, not unbounded. Mirrors
/// `exec::adapter::effective_timeout_ms`'s ceiling pattern: a grant may only
/// tighten this, never loosen past it, and an absent grant still gets
/// clamped here rather than passing the caller's raw request straight
/// through to the DB. 100k rows is generous for any interactive read (spec
/// 03's tools are not a bulk-export path) while bounding the in-memory
/// `Vec<Vec<Value>>` and JSON response size a single request can force the
/// gateway to build, even after the #136 row-cap-cancel fix stops the *DB
/// connection* from being pinned by an oversized ask.
pub(crate) const GATEWAY_ROW_LIMIT_CEILING: u32 = 100_000;

pub use audit_dispatch::RequestContext;
pub use context::ToolCtx;

// Re-export canonical names so dispatch and the advertised capability can
// never drift apart.
pub use crate::mcp::protocol::DESCRIBE_SCHEMA_TOOL as DESCRIBE_SCHEMA;
pub use crate::mcp::protocol::EXPLAIN_TOOL as EXPLAIN;
pub use crate::mcp::protocol::GET_QUERY_HISTORY_TOOL as GET_QUERY_HISTORY;
pub use crate::mcp::protocol::LIST_DATABASES_TOOL as LIST_DATABASES;
pub use crate::mcp::protocol::LIST_SERVERS_TOOL as LIST_SERVERS;
pub use crate::mcp::protocol::RUN_QUERY_TOOL as RUN_QUERY;
pub use crate::mcp::protocol::SAMPLE_TABLE_TOOL as SAMPLE_TABLE;

/// Audit-row and metric `tool` for a call that named no known tool. The
/// caller's string is caller-controlled and unbounded, so it rides in
/// `error_message` (capped), never in a metric label.
const UNKNOWN_TOOL: &str = "unknown";
/// Bytes of an unknown tool name kept in the audit row.
const UNKNOWN_TOOL_NAME_MAX_BYTES: usize = 64;

#[derive(Debug, Deserialize)]
struct CallParams {
    name: String,
    #[serde(default)]
    arguments: Option<Value>,
}

/// Route a `tools/call` JSON-RPC request to its tool. `ctx.identity` is the
/// authenticated caller; the transport refuses before this point if there is
/// none.
///
/// Per CLAUDE.md, every tool dispatch is a tracing span with `request_id`,
/// `user`, `server`, `database`. For tools that don't address a specific
/// server/db (e.g. `list_servers`) those fields render empty; per-DB tools
/// (`run_query`) fill them from the call arguments.
pub async fn dispatch_call(id: Value, ctx: ToolCtx<'_>, params: Option<Value>) -> Response {
    let call: CallParams = match params.map(serde_json::from_value::<CallParams>) {
        Some(Ok(c)) => c,
        _ => {
            return audit_dispatch::reject_arguments(
                ctx,
                id,
                UNKNOWN_TOOL,
                "missing or invalid `name`",
            )
            .await;
        }
    };

    // Per-DB tools (`run_query`) carry `server`/`database` in their arguments;
    // surface them on the span so every dispatch trace ties to a target.
    // Other tools (`list_servers`) leave both empty by design.
    let (span_server, span_database) = span_targets(&call);

    // Field names are the log contract documented in
    // docs/deployment/logging.md (issue #14): `user_sub`, `db` — Alloy/Loki
    // parsers key off these directly. Renaming silently breaks consumers.
    //
    // `request_id` is `ctx.request.request_id` (gateway-minted), NOT the
    // client's JSON-RPC `id` — that value is caller-controlled (arbitrary
    // JSON, unbounded length, no uniqueness guarantee) and is only ever
    // echoed back in the response envelope. Using the gateway UUID here
    // keeps this span's `request_id` and the eventual `audit_calls.request_id`
    // the same value, so a log line and its audit row always correlate.
    let span = info_span!(
        "tool_dispatch",
        request_id = %ctx.request.request_id,
        user_sub = %ctx.identity.user_sub,
        tool = %call.name,
        server = span_server,
        db = span_database,
    );

    let args = call.arguments;

    // `.instrument(span)`, not `span.enter()` held across the `.await`s
    // below. A sync `Entered` guard doesn't track task suspension on a
    // multi-threaded runtime: while this future is parked at an `.await`,
    // the executor can poll a DIFFERENT task on the same OS thread, and
    // that task's log events would be misattributed into this span until
    // this future resumes and the guard finally drops. `Instrument`
    // properly enters/exits the span around each individual poll, so
    // interleaved tasks never see it as "current."
    async move {
        match call.name.as_str() {
            LIST_SERVERS => list_servers::run(ctx, id).await,
            LIST_DATABASES => list_databases::run(ctx, id, args).await,
            DESCRIBE_SCHEMA => describe_schema::run(ctx, id, args).await,
            SAMPLE_TABLE => sample_table::run(ctx, id, args).await,
            EXPLAIN => explain::run(ctx, id, args).await,
            RUN_QUERY => run_query::run(ctx, id, args).await,
            GET_QUERY_HISTORY => get_query_history::run(ctx, id, args).await,
            other => {
                let name = prefix_at_char_boundary(other, UNKNOWN_TOOL_NAME_MAX_BYTES);
                let message = format!("unknown tool: {name}");
                audit_dispatch::reject_arguments(ctx, id, UNKNOWN_TOOL, &message).await
            }
        }
    }
    .instrument(span)
    .await
}

/// Pull `server`/`database` out of `tools/call` arguments for the dispatch
/// span. Tools that don't address a specific target (`list_servers`) get
/// empty strings; per-DB tools (`run_query`) and server-scoped tools
/// (`list_databases`) fill in what they have.
fn span_targets(call: &CallParams) -> (&str, &str) {
    if matches!(call.name.as_str(), LIST_SERVERS) {
        return ("", "");
    }
    let args = match call.arguments.as_ref() {
        Some(a) => a,
        None => return ("", ""),
    };
    let server = args.get("server").and_then(Value::as_str).unwrap_or("");
    let database = args.get("database").and_then(Value::as_str).unwrap_or("");
    (server, database)
}
