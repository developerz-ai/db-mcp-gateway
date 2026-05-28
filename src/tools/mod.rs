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

pub mod list_servers;
pub mod run_query;

use serde::Deserialize;
use serde_json::Value;
use tracing::info_span;

use crate::auth::Identity;
use crate::config::ConfigFile;
use crate::exec::PoolRegistry;
use crate::transport::jsonrpc::{ErrorObject, Response};

// Re-export canonical names so dispatch and the advertised capability can
// never drift apart.
pub use crate::transport::protocol::LIST_SERVERS_TOOL as LIST_SERVERS;
pub use crate::transport::protocol::RUN_QUERY_TOOL as RUN_QUERY;

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
pub async fn dispatch_call(
    id: Value,
    identity: Option<&Identity>,
    config: &ConfigFile,
    registry: &PoolRegistry,
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

    let span = info_span!(
        "tool_dispatch",
        request_id = %id,
        user = %identity.user_sub,
        tool = %call.name,
        server = "",
        database = "",
    );
    let _enter = span.enter();

    match call.name.as_str() {
        LIST_SERVERS => list_servers::run(id, identity, config, call.arguments),
        RUN_QUERY => run_query::run(id, identity, config, registry, call.arguments).await,
        other => Response::error(
            id,
            ErrorObject::invalid_params(format!("unknown tool: {other}")),
        ),
    }
}
