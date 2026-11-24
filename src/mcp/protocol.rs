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
pub const WHOAMI_TOOL: &str = "whoami";

/// Response to `initialize` — the MCP handshake greeting.
#[derive(Debug, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: &'static str,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    /// How to use the tools: the agent's system-prompt hint (MCP
    /// `InitializeResult.instructions`).
    pub instructions: &'static str,
}

/// The `initialize` instructions (built in `super::instructions`), rendered
/// once from the gateway's real limits.
pub static INSTRUCTIONS: LazyLock<String> = LazyLock::new(super::instructions::build);

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
            instructions: INSTRUCTIONS.as_str(),
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
    pub title: &'static str,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    pub annotations: ToolAnnotations,
}

/// MCP tool hints. Untrusted by clients, so they only describe what the
/// gateway already enforces; every target here is a configured database, so
/// none is open-world.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    read_only_hint: bool,
    /// Meaningful only when `read_only_hint` is false (MCP 2025-06-18).
    #[serde(skip_serializing_if = "Option::is_none")]
    destructive_hint: Option<bool>,
    open_world_hint: bool,
}

impl ToolAnnotations {
    /// The tool never changes anything in a target or the gateway.
    pub const fn read_only() -> Self {
        Self {
            read_only_hint: true,
            destructive_hint: None,
            open_world_hint: false,
        }
    }

    /// The tool can change state; `destructive` when that change can delete
    /// or overwrite data.
    pub const fn mutating(destructive: bool) -> Self {
        Self {
            read_only_hint: false,
            destructive_hint: Some(destructive),
            open_world_hint: false,
        }
    }
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
