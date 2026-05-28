//! Integration tests: drive real MCP requests over HTTP against a booted gateway.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport::{self, AppState, protocol};
use serde_json::{Value, json};

/// Boot the gateway on an ephemeral port and return the full MCP endpoint URL.
///
/// These tests exercise the transport wire protocol only; `AppState { auth:
/// None }` bypasses auth wiring by design. Auth/session behavior is covered by
/// `tests/auth_e2e.rs`. Audit-row assertions are intentionally omitted here
/// because this harness has no audit integration yet (audit module lands in a
/// later issue).
async fn spawn_gateway() -> String {
    let config = Config {
        bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        mcp_path: "/mcp".to_string(),
        ..Config::default()
    };
    let app = transport::router(&config, AppState::for_tests());
    let listener = tokio::net::TcpListener::bind(config.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/mcp")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn initialize_returns_protocol_version() {
    let url = spawn_gateway().await;
    let response = client()
        .post(&url)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(
        body["result"]["protocolVersion"],
        protocol::PROTOCOL_VERSION
    );
}

#[tokio::test]
async fn tools_list_advertises_all_registered_tools() {
    let url = spawn_gateway().await;
    let response = client()
        .post(&url)
        .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .send()
        .await
        .unwrap();

    let body: Value = response.json().await.unwrap();
    let tools = body["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "list_servers",
        "list_databases",
        "describe_schema",
        "sample_table",
        "explain",
        "run_query",
    ] {
        assert!(
            names.contains(&expected),
            "expected `{expected}` in advertised tools: {body}"
        );
    }
}

#[tokio::test]
async fn notification_is_acknowledged_without_body() {
    let url = spawn_gateway().await;
    let response = client()
        .post(&url)
        .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 202);
}

#[tokio::test]
async fn sse_endpoint_emits_greeting() {
    let url = spawn_gateway().await;
    let mut response = client()
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let content_type = response.headers()["content-type"].to_str().unwrap();
    assert!(
        content_type.contains("text/event-stream"),
        "unexpected content-type: {content_type}"
    );

    let chunk = response.chunk().await.unwrap().expect("greeting chunk");
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("greeting"), "missing greeting event: {text}");
    assert!(
        text.contains(protocol::PROTOCOL_VERSION),
        "missing protocol version: {text}"
    );
}
