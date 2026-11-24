//! Concurrency shedding on the MCP endpoint (plan 101 slice 06 M15): a shed
//! `/mcp` request answers a JSON-RPC error whose `data` carries the stable
//! code and `retry_after_s`, keeping the HTTP status and `Retry-After`; an
//! admitted one reports the caller's budget in headers. Other gated routes
//! keep the `{error: {category, code}}` body.
//!
//! The limiter runs in a minimal router with a gate-held handler, so the
//! test controls exactly which request holds which permit.

// audit-guard: exempt — no tool dispatch: a shed request is a log line and a metric, never an audit row (spec 03 §Errors)

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::post;
use db_mcp_gateway::auth::{Identity, IdentityKind, SessionId};
use db_mcp_gateway::transport::limit::{self, ConcurrencyLimiter};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::sync::{Notify, Semaphore};

use crate::common::gateway::{bind, serve};

const MCP_PATH: &str = "/mcp";
const OTHER_PATH: &str = "/auth/logout";

#[derive(Clone)]
struct Gate {
    entered: Arc<Notify>,
    release: Arc<Semaphore>,
}

async fn held(State(gate): State<Gate>) -> &'static str {
    gate.entered.notify_one();
    if let Ok(permit) = gate.release.acquire().await {
        permit.forget();
    }
    "{}"
}

async fn as_alice(mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(Identity {
        session_id: SessionId::new(),
        user_sub: "alice".into(),
        user_email: "alice@example.com".into(),
        groups: vec![],
        issued_at: chrono::Utc::now(),
        kind: IdentityKind::Sso,
    });
    next.run(req).await
}

/// A gateway-shaped router: `MCP_PATH` and `OTHER_PATH` behind one limiter.
async fn spawn(global: usize, per_identity: usize) -> (String, Gate) {
    let gate = Gate {
        entered: Arc::new(Notify::new()),
        release: Arc::new(Semaphore::new(0)),
    };
    let limiter =
        Arc::new(ConcurrencyLimiter::with_caps(global, per_identity).with_mcp_path(MCP_PATH));
    let app = Router::new()
        .route(MCP_PATH, post(held))
        .route(OTHER_PATH, post(held))
        .route_layer(middleware::from_fn_with_state(limiter, limit::enforce))
        .route_layer(middleware::from_fn(as_alice))
        .with_state(gate.clone());
    let (listener, addr) = bind().await;
    serve(listener, app);
    (format!("http://{addr}"), gate)
}

fn post_to(url: String) -> tokio::task::JoinHandle<reqwest::Response> {
    tokio::spawn(async move {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
            .post(url)
            .json(&json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}))
            .send()
            .await
            .unwrap()
    })
}

/// Start a request on `path` and wait until it holds its permits.
async fn hold(base: &str, gate: &Gate, path: &str) -> tokio::task::JoinHandle<reqwest::Response> {
    let entered = gate.entered.notified();
    let request = post_to(format!("{base}{path}"));
    tokio::time::timeout(Duration::from_secs(10), entered)
        .await
        .expect("first request did not reach the held handler");
    request
}

fn header<'a>(response: &'a reqwest::Response, name: &str) -> &'a str {
    response.headers()[name].to_str().unwrap()
}

fn assert_jsonrpc_shed(body: &Value, code: &str) {
    assert_eq!(body["jsonrpc"], "2.0", "{body}");
    assert_eq!(body["id"], Value::Null, "the body was never read: {body}");
    assert_eq!(body["error"]["code"], -32000, "{body}");
    assert!(body["error"]["message"].is_string(), "{body}");
    let data = &body["error"]["data"];
    assert_eq!(data["code"], code, "{body}");
    assert_eq!(data["retry_after_s"], 1, "{body}");
    assert!(data["request_id"].is_string(), "{body}");
}

#[tokio::test]
async fn per_identity_shed_on_mcp_is_a_jsonrpc_error_with_budget_headers() {
    let (base, gate) = spawn(10, 1).await;
    let first = hold(&base, &gate, MCP_PATH).await;

    let shed = post_to(format!("{base}{MCP_PATH}")).await.unwrap();
    assert_eq!(shed.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&shed, "retry-after"), "1");
    assert_eq!(header(&shed, "x-dbmcp-concurrency-limit"), "1");
    assert_eq!(header(&shed, "x-dbmcp-concurrency-remaining"), "0");
    let body: Value = shed.json().await.unwrap();
    assert_jsonrpc_shed(&body, "concurrency_limit_exceeded");
    assert_eq!(body["error"]["data"]["category"], "rate_limited");

    gate.release.add_permits(1);
    let admitted = first.await.unwrap();
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(header(&admitted, "x-dbmcp-concurrency-limit"), "1");
    assert_eq!(header(&admitted, "x-dbmcp-concurrency-remaining"), "0");
}

#[tokio::test]
async fn global_shed_on_mcp_is_a_jsonrpc_error() {
    let (base, gate) = spawn(1, 4).await;
    let first = hold(&base, &gate, MCP_PATH).await;

    let shed = post_to(format!("{base}{MCP_PATH}")).await.unwrap();
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header(&shed, "retry-after"), "1");
    let body: Value = shed.json().await.unwrap();
    assert_jsonrpc_shed(&body, "service_overloaded");
    assert_eq!(body["error"]["data"]["category"], "overloaded");

    gate.release.add_permits(1);
    let admitted = first.await.unwrap();
    assert_eq!(header(&admitted, "x-dbmcp-concurrency-limit"), "4");
    assert_eq!(header(&admitted, "x-dbmcp-concurrency-remaining"), "3");
}

#[tokio::test]
async fn other_gated_routes_keep_the_plain_error_body() {
    let (base, gate) = spawn(10, 1).await;
    let first = hold(&base, &gate, OTHER_PATH).await;

    let shed = post_to(format!("{base}{OTHER_PATH}")).await.unwrap();
    assert_eq!(shed.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&shed, "retry-after"), "1");
    assert!(shed.headers().get("x-dbmcp-concurrency-limit").is_none());
    let body: Value = shed.json().await.unwrap();
    assert_eq!(
        body["error"]["code"], "concurrency_limit_exceeded",
        "{body}"
    );
    assert_eq!(body["error"]["category"], "rate_limited", "{body}");
    assert!(body["request_id"].is_string(), "{body}");

    gate.release.add_permits(1);
    let admitted = first.await.unwrap();
    assert!(
        admitted
            .headers()
            .get("x-dbmcp-concurrency-limit")
            .is_none()
    );
}
