//! MCP protocol constants and the typed payloads the gateway returns.
//!
//! Wire transport is Streamable HTTP — see docs/initial-idea/02-architecture.md.

use serde::Serialize;
use serde_json::{Value, json};

/// MCP protocol revision this gateway speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Advertised server identity (no host/credential info — that never leaves here).
pub const SERVER_NAME: &str = "db-mcp-gateway";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The placeholder tool that exists only to prove the dispatch path end to end.
/// Removed when real tools land (issue #3).
pub const PING_TOOL: &str = "ping";

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

impl ToolsListResult {
    /// The scaffold tool surface — a single no-op `ping`. Real tools: issue #3.
    pub fn scaffold() -> Self {
        Self {
            tools: vec![Tool {
                name: PING_TOOL,
                description: "Liveness placeholder; returns \"pong\". Replaced by real tools (issue #3).",
                input_schema: json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
            }],
        }
    }
}

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
