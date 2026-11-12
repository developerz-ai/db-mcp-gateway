//! Integration tests: drive real MCP requests over HTTP against a booted
//! gateway — JSON-RPC framing, the id rule, error shapes and request ids.
//!
//! Wire protocol only: nothing here dispatches a DB tool, so there are no
//! audit rows to assert (tool audit coverage lives in the tool e2e suites).

mod common;

use std::time::Duration;

use common::gateway::{
    EMPTY_YAML, SERVICE_TOKEN, SERVICE_YAML, authless_state, bind, offline_state, serve,
    spawn_authless, spawn_offline,
};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::mcp::protocol;
use db_mcp_gateway::transport::{self, TransportError};
use reqwest::StatusCode;
use serde_json::{Value, json};

/// Protocol-only router (no bearer auth); returns the MCP endpoint URL.
async fn spawn_gateway() -> String {
    let (listener, addr) = bind().await;
    let config = Config {
        bind: addr,
        ..Config::default()
    };
    serve(listener, transport::test_router(&config, authless_state()));
    format!("http://{addr}/mcp")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn post_raw(url: &str, body: &str) -> (StatusCode, Value) {
    let response = client()
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .await
        .unwrap();
    (response.status(), response.json().await.unwrap())
}

/// The `x-request-id` header every response carries.
fn request_id(response: &reqwest::Response) -> String {
    response.headers()["x-request-id"]
        .to_str()
        .expect("x-request-id is ASCII")
        .to_owned()
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
    let (_, body) = post_raw(&url, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).await;
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
        "get_query_history",
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
    for method in ["notifications/initialized", "tools/call"] {
        let response = client()
            .post(&url)
            .json(&json!({"jsonrpc": "2.0", "method": method}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202, "{method}");
        assert!(response.bytes().await.unwrap().is_empty(), "{method}");
    }
}

/// MCP `RequestId` is `string | number`. Any other id is `invalid_request`
/// before authz/query/audit work, on both the tool and the stateless path,
/// with the id echoed back verbatim.
#[tokio::test]
async fn unsupported_id_types_are_invalid_request_on_every_path() {
    let url = spawn_gateway().await;
    for method in ["tools/call", "initialize"] {
        for id in [
            json!(true),
            json!([1, 2]),
            json!({"nested": true}),
            json!(1.5),
        ] {
            let request = json!({
                "jsonrpc": "2.0", "id": id, "method": method,
                "params": {"name": "list_servers"}
            });
            let (status, body) = post_raw(&url, &request.to_string()).await;
            assert_eq!(status, 200);
            assert_eq!(
                body,
                json!({"jsonrpc": "2.0", "id": id,
                       "error": {"code": -32600, "message": "Invalid request"}}),
                "{method} id {id}"
            );
        }
    }
}

/// Golden JSON for every framing error: malformed JSON, a batch, valid JSON
/// that is not a request, and a request with a recoverable id.
#[tokio::test]
async fn framing_errors_have_stable_json_rpc_shapes() {
    let url = spawn_gateway().await;
    let cases = [
        (
            "{not json",
            json!({"jsonrpc": "2.0", "id": null,
                   "error": {"code": -32700, "message": "Parse error"}}),
        ),
        (
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            json!({"jsonrpc": "2.0", "id": null,
                   "error": {"code": -32600, "message": "batch requests are not supported"}}),
        ),
        (
            "42",
            json!({"jsonrpc": "2.0", "id": null,
                   "error": {"code": -32600, "message": "Invalid request"}}),
        ),
        (
            r#"{"jsonrpc":"2.0","id":"abc"}"#,
            json!({"jsonrpc": "2.0", "id": "abc",
                   "error": {"code": -32600, "message": "Invalid request"}}),
        ),
    ];
    for (body, expected) in cases {
        let (status, got) = post_raw(&url, body).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(got, expected, "{body}");
    }
}

#[tokio::test]
async fn oversized_body_is_refused_with_a_json_rpc_error() {
    let base = spawn_offline(Config::default(), SERVICE_YAML).await;
    let huge = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "x".repeat(2 * 1024 * 1024)
    );
    let response = client()
        .post(format!("{base}/mcp"))
        .bearer_auth(SERVICE_TOKEN)
        .body(huge)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["id"], Value::Null);
    assert_eq!(body["error"]["code"], -32600);
}

/// Every response — success, 401, 404, 405 — carries a gateway-minted
/// `x-request-id`; a client-supplied one is never echoed as the gateway's.
#[tokio::test]
async fn every_response_carries_a_gateway_request_id() {
    let base = spawn_authless(Config::default()).await;
    let http = client();

    let ok = http.get(format!("{base}/healthz")).send().await.unwrap();
    let not_found = http.get(format!("{base}/nope")).send().await.unwrap();
    let with_client_id = http
        .get(format!("{base}/healthz"))
        .header("x-request-id", "client-chosen-1")
        .send()
        .await
        .unwrap();
    for response in [&ok, &not_found, &with_client_id] {
        let id = request_id(response);
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "not a UUID: {id}");
    }
    assert_ne!(request_id(&ok), request_id(&not_found));
    assert_ne!(request_id(&with_client_id), "client-chosen-1");
}

/// The 401 body carries the same id as the header (golden shape).
#[tokio::test]
async fn unauthorized_body_names_the_request_id() {
    let base = spawn_authless(Config::default()).await;
    let response = client()
        .post(format!("{base}/mcp"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let id = request_id(&response);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body,
        json!({
            "error": {"category": "unauthenticated", "code": "missing_bearer"},
            "login_url": "/auth/login",
            "request_id": id,
        })
    );
}

/// The gateway initiates no server→client messages, so `GET /mcp` is 405
/// (MCP 2025-06-18 Streamable HTTP) rather than an idle, unauthenticated
/// stream pinning a socket.
#[tokio::test]
async fn get_on_the_mcp_endpoint_is_method_not_allowed() {
    let base = spawn_authless(Config::default()).await;
    let response = client()
        .get(format!("{base}/mcp"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "POST");
    assert!(response.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn router_refuses_a_zero_concurrency_cap() {
    for config in [
        Config {
            max_concurrent_requests: 0,
            ..Config::default()
        },
        Config {
            max_concurrent_per_identity: 0,
            ..Config::default()
        },
    ] {
        let state = offline_state("http://localhost:8443", EMPTY_YAML);
        assert!(matches!(
            transport::router(&config, state),
            Err(TransportError::ZeroConcurrencyCap)
        ));
    }
}
