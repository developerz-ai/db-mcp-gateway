//! `tools/list` is a promise; the match in `tools::dispatch_call` is the only
//! thing that keeps it, and nothing in the type system ties the two together.
//!
//! That gap is not theoretical. #187 shipped `get_query_history`; #189 rebuilt
//! itself on a pre-#187 base and deleted the handler and its dispatch arm while
//! leaving the advertisement in `ToolsListResult::current()`. For two weeks the
//! gateway offered agents a tool that answered `unknown tool`, with CI green the
//! whole time (#212).
//!
//! No database required — a dispatch that gets as far as "no state DB" has
//! already proved the arm exists, which is the only claim here.

use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::config::ConfigFile;
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::tools::{RequestContext, dispatch_call};
use db_mcp_gateway::transport::protocol::ToolsListResult;
use serde_json::json;

fn identity() -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: "sub-1".to_string(),
        user_email: "dev@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
    }
}

/// Every name in `tools/list` must reach a real arm in `tools/call`.
///
/// Deliberately asserts nothing about what each tool *does* with empty
/// arguments — that varies (`invalid_params` for a missing `server`, an
/// audit-unavailable error with no state DB) and is each tool's own test's
/// business. The single claim is that no advertised name falls through to the
/// catch-all.
#[tokio::test]
async fn every_advertised_tool_has_a_dispatch_arm() {
    let identity = identity();
    let config = ConfigFile::from_yaml_str("servers: []\n").expect("empty config parses");
    let registry = AdapterRegistry::new();
    let request_ctx = RequestContext::default();

    for tool in ToolsListResult::current().tools {
        let response = dispatch_call(
            json!(1),
            Some(&identity),
            &config,
            &registry,
            None,
            None,
            &request_ctx,
            Some(json!({ "name": tool.name, "arguments": {} })),
        )
        .await;

        if let Some(err) = response.error {
            assert!(
                !err.message.contains("unknown tool"),
                "`{}` is advertised in tools/list but tools/call cannot dispatch it: {}",
                tool.name,
                err.message,
            );
        }
    }
}
