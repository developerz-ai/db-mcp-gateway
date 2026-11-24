//! One MCP `tools/call` over HTTP as a logged-in caller — the request every
//! tool e2e test sends. Tests that need the raw response (status, headers)
//! build their own; this one returns the parsed JSON-RPC body.

use std::time::Duration;

use serde_json::{Value, json};

use super::gateway::LoggedInGateway;

/// POST `tools/call` for `tool` with `arguments`; the JSON-RPC response.
pub async fn call_tool(gw: &LoggedInGateway, tool: &str, arguments: Value) -> Value {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&gw.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
