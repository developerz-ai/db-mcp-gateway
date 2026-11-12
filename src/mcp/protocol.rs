//! MCP protocol constants and the typed payloads the gateway returns.
//!
//! Wire transport is Streamable HTTP — see website/docs/initial-idea/02-architecture.md.

use std::sync::LazyLock;

use serde::Serialize;
use serde_json::Value;

/// MCP protocol revision this gateway speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Advertised server identity (no host/credential info — that never leaves here).
pub const SERVER_NAME: &str = "db-mcp-gateway";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Logical names of the MCP tools the gateway exposes. The string values are
/// the protocol-level tool names agents pass to `tools/call`.
pub const LIST_SERVERS_TOOL: &str = "list_servers";
pub const LIST_DATABASES_TOOL: &str = "list_databases";
pub const DESCRIBE_SCHEMA_TOOL: &str = "describe_schema";
pub const SAMPLE_TABLE_TOOL: &str = "sample_table";
pub const EXPLAIN_TOOL: &str = "explain";
pub const RUN_QUERY_TOOL: &str = "run_query";
pub const GET_QUERY_HISTORY_TOOL: &str = "get_query_history";
pub const TABLE_STATS_TOOL: &str = "table_stats";
pub const DB_ACTIVITY_TOOL: &str = "db_activity";
pub const CANCEL_QUERY_TOOL: &str = "cancel_query";

/// Response to `initialize` — the MCP handshake greeting.
#[derive(Debug, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: &'static str,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

impl InitializeResult {
    pub fn new() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            capabilities: ServerCapabilities {
                tools: ToolsCapability {},
            },
            server_info: ServerInfo {
                name: SERVER_NAME,
                version: SERVER_VERSION,
            },
        }
    }
}

impl Default for InitializeResult {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct ServerCapabilities {
    pub tools: ToolsCapability,
}

/// Empty for now; serializes to `{}` to signal "tools are supported".
#[derive(Debug, Serialize)]
pub struct ToolsCapability {}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: &'static str,
    pub version: &'static str,
}

/// Result for methods that return an empty object (e.g. `ping`).
#[derive(Debug, Serialize)]
pub struct EmptyResult {}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Serialize)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
}

/// The `tools/list` payload (built in `super::tool_list`). Static, so its JSON
/// schemas are built once per process rather than on every call.
pub static TOOLS_LIST: LazyLock<ToolsListResult> = LazyLock::new(ToolsListResult::build);

#[derive(Debug, Serialize)]
pub struct CallToolResult {
    pub content: Vec<TextContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

impl CallToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![TextContent::new(text)],
            is_error: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TextContent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub text: String,
}

impl TextContent {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            kind: "text",
            text: text.into(),
        }
    }
}
