//! MCP tool implementations.
//!
//! Each tool is a handler with shape
//! `run(id, identity, config, [registry], args) -> jsonrpc::Response`. The
//! transport routes `tools/call` to `dispatch_call`, which fans out by tool
//! name.
//!
//! Security-required (see CLAUDE.md). Every tool that returns config data
//! MUST go through a credential-free view type (see `SafeServerView`); never
//! serialize a `crate::config::Server` to the wire.

pub mod audit_dispatch;
pub mod describe_schema;
pub mod explain;
pub mod list_databases;
pub mod list_servers;
pub mod run_query;
pub mod sample_table;

use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use tracing::info_span;

use crate::auth::Identity;
use crate::authz::PermissionsCache;
use crate::config::{ConfigFile, ServerKind};
use crate::exec::AdapterRegistry;
use crate::transport::jsonrpc::{ErrorObject, Response};

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

pub use audit_dispatch::RequestContext;

// Re-export canonical names so dispatch and the advertised capability can
// never drift apart.
pub use crate::transport::protocol::DESCRIBE_SCHEMA_TOOL as DESCRIBE_SCHEMA;
pub use crate::transport::protocol::EXPLAIN_TOOL as EXPLAIN;
pub use crate::transport::protocol::LIST_DATABASES_TOOL as LIST_DATABASES;
pub use crate::transport::protocol::LIST_SERVERS_TOOL as LIST_SERVERS;
pub use crate::transport::protocol::RUN_QUERY_TOOL as RUN_QUERY;
pub use crate::transport::protocol::SAMPLE_TABLE_TOOL as SAMPLE_TABLE;

#[derive(Debug, Deserialize)]
struct CallParams {
    name: String,
    #[serde(default)]
    arguments: Option<Value>,
}

/// Route a `tools/call` JSON-RPC request to its tool. Identity is the
/// authenticated caller (the bearer-auth middleware guarantees presence on
/// `/mcp` POST; the `Option` lets the caller surface "anonymous" as a defined
/// internal-error rather than panicking).
///
/// Per CLAUDE.md, every tool dispatch is a tracing span with `request_id`,
/// `user`, `server`, `database`. For tools that don't address a specific
/// server/db (e.g. `list_servers`) those fields render empty; per-DB tools
/// (`run_query`) fill them from the call arguments.
// Per-request fan-out — every arg is a distinct slice of request state owned
// by AppState. Bundling into a ToolContext would lengthen call sites without
// reducing what each handler needs to know.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_call(
    id: Value,
    identity: Option<&Identity>,
    config: &ConfigFile,
    registry: &AdapterRegistry,
    permissions_cache: Option<&PermissionsCache>,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    params: Option<Value>,
) -> Response {
    let Some(identity) = identity else {
        return Response::error(id, ErrorObject::internal("missing identity"));
    };

    let call: CallParams = match params.map(serde_json::from_value::<CallParams>) {
        Some(Ok(c)) => c,
        _ => {
            return Response::error(id, ErrorObject::invalid_params("missing or invalid `name`"));
        }
    };

    // Per-DB tools (`run_query`) carry `server`/`database` in their arguments;
    // surface them on the span so every dispatch trace ties to a target.
    // Other tools (`list_servers`) leave both empty by design.
    let (span_server, span_database) = span_targets(&call);

    // Field names are the log contract documented in
    // docs/deployment/logging.md (issue #14): `user_sub`, `db` — Alloy/Loki
    // parsers key off these directly. Renaming silently breaks consumers.
    let span = info_span!(
        "tool_dispatch",
        request_id = %id,
        user_sub = %identity.user_sub,
        tool = %call.name,
        server = span_server,
        db = span_database,
    );
    let _enter = span.enter();

    match call.name.as_str() {
        LIST_SERVERS => {
            list_servers::run(
                id,
                identity,
                config,
                permissions_cache,
                state_db,
                request_ctx,
                call.arguments,
            )
            .await
        }
        LIST_DATABASES => {
            list_databases::run(
                id,
                identity,
                config,
                permissions_cache,
                state_db,
                request_ctx,
                call.arguments,
            )
            .await
        }
        DESCRIBE_SCHEMA => {
            describe_schema::run(
                id,
                identity,
                config,
                registry,
                permissions_cache,
                state_db,
                request_ctx,
                call.arguments,
            )
            .await
        }
        SAMPLE_TABLE => {
            sample_table::run(
                id,
                identity,
                config,
                registry,
                permissions_cache,
                state_db,
                request_ctx,
                call.arguments,
            )
            .await
        }
        EXPLAIN => {
            explain::run(
                id,
                identity,
                config,
                registry,
                permissions_cache,
                state_db,
                request_ctx,
                call.arguments,
            )
            .await
        }
        RUN_QUERY => {
            run_query::run(
                id,
                identity,
                config,
                registry,
                permissions_cache,
                state_db,
                request_ctx,
                call.arguments,
            )
            .await
        }
        other => Response::error(
            id,
            ErrorObject::invalid_params(format!("unknown tool: {other}")),
        ),
    }
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
