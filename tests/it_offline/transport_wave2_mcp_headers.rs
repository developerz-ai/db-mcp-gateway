//! MCP Streamable HTTP header rules on `POST <mcp_path>` (2025-06-18):
//! a present `MCP-Protocol-Version` must be one the gateway speaks (else
//! `400`), an absent one is the spec's backwards-compatible default, and the
//! body must be declared `application/json` (else `415`).
//!
//! Wire protocol only: no `tools/call` reaches dispatch, so there is no audit
//! row to assert.

use std::time::Duration;

use crate::common::gateway::{authless_state, bind, serve};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::mcp::protocol;
use db_mcp_gateway::transport;
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn spawn_gateway() -> String {
    let (listener, addr) = bind().await;
    let config = Config {
        bind: addr,
        ..Config::default()
    };
    serve(listener, transport::test_router(&config, authless_state()));
    format!("http://{addr}/mcp")
}

fn ping() -> String {
    json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}).to_string()
}

async fn post(
    url: &str,
    content_type: Option<&str>,
    version: Option<&str>,
    body: String,
) -> (StatusCode, Value) {
    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .post(url)
        .body(body);
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    if let Some(version) = version {
        request = request.header("mcp-protocol-version", version);
    }
    let response = request.send().await.unwrap();
    (response.status(), response.json().await.unwrap())
}

#[tokio::test]
async fn unsupported_protocol_version_is_400() {
    let url = spawn_gateway().await;
    for bogus in ["1999-01-01", "banana", "2025-06-18x", "2025-03-26"] {
        let (status, body) = post(&url, Some("application/json"), Some(bogus), ping()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bogus:?}");
        assert_eq!(body["error"]["code"], -32600, "{bogus:?}");
        assert_eq!(body["id"], 7, "the request id is echoed");
    }
}

#[tokio::test]
async fn negotiated_or_absent_protocol_version_is_served() {
    let url = spawn_gateway().await;
    for version in [Some(protocol::PROTOCOL_VERSION), None] {
        let (status, body) = post(&url, Some("application/json"), version, ping()).await;
        assert_eq!(status, StatusCode::OK, "{version:?}");
        assert_eq!(body["result"], json!({}), "{version:?}");
    }
}

/// `initialize` precedes negotiation, so its header (if any) is not judged:
/// the response names the version the client must use from then on.
#[tokio::test]
async fn initialize_is_not_judged_by_the_version_header() {
    let url = spawn_gateway().await;
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (status, body) = post(
        &url,
        Some("application/json"),
        Some("2099-01-01"),
        init.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["protocolVersion"],
        protocol::PROTOCOL_VERSION
    );
}

#[tokio::test]
async fn non_json_content_type_is_415() {
    let url = spawn_gateway().await;
    for content_type in [Some("text/plain"), None, Some("application/jsonx")] {
        let (status, body) = post(&url, content_type, None, ping()).await;
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?}"
        );
        assert_eq!(body["error"]["code"], -32600, "{content_type:?}");
    }
}

#[tokio::test]
async fn json_content_type_with_parameters_is_accepted() {
    let url = spawn_gateway().await;
    for content_type in ["application/json; charset=utf-8", "Application/JSON"] {
        let (status, _) = post(&url, Some(content_type), None, ping()).await;
        assert_eq!(status, StatusCode::OK, "{content_type}");
    }
}
