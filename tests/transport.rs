//! Integration tests: drive real MCP requests over HTTP against a booted gateway.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport::{self, AppState, protocol};
use serde_json::{Value, json};

/// Boot the gateway on an ephemeral port and return the full MCP endpoint URL.
///
/// These tests exercise the transport wire protocol only, without authentication.
/// Auth/session behavior is covered by `tests/auth_e2e.rs`. Audit-row assertions
/// are intentionally omitted here because this harness has no audit integration yet
/// (audit module lands in a later issue).
async fn spawn_gateway() -> String {
    use db_mcp_gateway::config::ConfigFile;
    use db_mcp_gateway::exec::AdapterRegistry;
    use db_mcp_gateway::transport::ClientRegistry;
    use std::sync::Arc;

    let config = Config {
        bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        mcp_path: "/mcp".to_string(),
        ..Config::default()
    };
    let state = AppState {
        auth: None,
        config: Arc::new(ConfigFile {
            servers: Vec::new(),
            permissions: Vec::new(),
            admin: None,
            permissions_store: None,
            service_accounts: Vec::new(),
        }),
        adapter_registry: AdapterRegistry::new(),
        state_db: None,
        shutdown: Default::default(),
        metrics: None,
        permissions_cache: None,
        permissions_repo: None,
        mcp_path: Arc::from("/mcp"),
        client_registry: ClientRegistry::default(),
    };
    let app = transport::test_router(&config, state);
    let listener = tokio::net::TcpListener::bind(config.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
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

/// MCP `RequestId` is `string | number`. A `tools/call` sent with a boolean,
/// array, object, or fractional-number id has no valid interpretation, so it
/// must be rejected as `invalid_request` before any authz/query/audit work —
/// same reasoning as the explicit-null case, and the id is echoed back so the
/// caller can correlate the failure.
#[tokio::test]
async fn tools_call_with_unsupported_id_type_is_invalid_request() {
    let url = spawn_gateway().await;
    for id in [
        json!(true),
        json!([1, 2]),
        json!({"nested": true}),
        json!(1.5),
    ] {
        let response = client()
            .post(&url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": "list_servers"}
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], -32600,
            "id {id}: expected invalid_request"
        );
        assert_eq!(
            body["id"], id,
            "id {id}: response must echo original id verbatim"
        );
    }
}

/// Same coverage for the stateless dispatch path (`initialize`): rejecting
/// unsupported id types must happen before method-specific work regardless
/// of which handler the method would route to.
#[tokio::test]
async fn stateless_method_with_unsupported_id_type_is_invalid_request() {
    let url = spawn_gateway().await;
    let response = client()
        .post(&url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": [1, 2, 3],
            "method": "initialize",
            "params": {}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["id"], json!([1, 2, 3]));
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
