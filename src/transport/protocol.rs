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

/// Logical names of the MCP tools the gateway exposes. The string values are
/// the protocol-level tool names agents pass to `tools/call`.
pub const LIST_SERVERS_TOOL: &str = "list_servers";
pub const LIST_DATABASES_TOOL: &str = "list_databases";
pub const DESCRIBE_SCHEMA_TOOL: &str = "describe_schema";
pub const SAMPLE_TABLE_TOOL: &str = "sample_table";
pub const EXPLAIN_TOOL: &str = "explain";
pub const RUN_QUERY_TOOL: &str = "run_query";

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
    /// Snapshot of the currently registered MCP tools. Grows as more tools
    /// land in later issues.
    pub fn current() -> Self {
        Self {
            tools: vec![
                Tool {
                    name: LIST_SERVERS_TOOL,
                    description: "List the database servers the caller is permitted to see. \
                                  Returns logical name, kind, and description — no connection info.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: LIST_DATABASES_TOOL,
                    description: "List databases on a configured server that the caller is \
                                  permitted to see. Returns logical name + description — \
                                  no connection info.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server": { "type": "string" }
                        },
                        "required": ["server"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: DESCRIBE_SCHEMA_TOOL,
                    description: "Return tables + columns + types for a given database. \
                                  Optional `schema` (default `public`) and `table` narrow \
                                  the result. No row data is returned.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "schema":   { "type": "string" },
                            "table":    { "type": "string" }
                        },
                        "required": ["server", "database"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: SAMPLE_TABLE_TOOL,
                    description: "Return a small sample of rows from a table — `SELECT * \
                                  FROM \"<schema>\".\"<table>\" LIMIT n`. Useful for \"what \
                                  does this data look like\" without writing SQL. Schema and \
                                  table identifiers must be plain alphanumerics.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "table":    { "type": "string" },
                            "schema":   { "type": "string" },
                            "limit":    { "type": "integer", "minimum": 1 }
                        },
                        "required": ["server", "database", "table"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: EXPLAIN_TOOL,
                    description: "Return the query plan for a SELECT/CTE via \
                                  `EXPLAIN (FORMAT JSON)`. SQL is AST-validated read-only \
                                  before wrapping; the query itself is not executed.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "sql":      { "type": "string" }
                        },
                        "required": ["server", "database", "sql"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: RUN_QUERY_TOOL,
                    description: "Execute SQL against a configured (server, database) under the \
                                  caller's grants. Returns columns, rows, truncation flag, and \
                                  elapsed_ms. Statement timeout + row cap enforced by policy.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "sql":      { "type": "string" },
                            "limit":    { "type": "integer", "minimum": 1 },
                            "reason":   { "type": "string" }
                        },
                        "required": ["server", "database", "sql"],
                        "additionalProperties": false
                    }),
                },
            ],
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
