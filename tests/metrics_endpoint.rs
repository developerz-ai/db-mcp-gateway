//! `/metrics` exposure (plan 101 slice 11 step 5): the scrape endpoint lives
//! on its own `METRICS_BIND` listener (src/startup/metrics.rs, unit-tested
//! there with its buckets), so the public router must not serve it — and no
//! series emitted on the request path may carry an identity or SQL label.
//!
//! Own test binary: the recorder install is process-global. The dispatch
//! case writes an audit row to the real state DB; run under the shared DB
//! lock.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::audit::assert_audit_outcome;
use common::cleanup::delete_audit_calls;
use common::env::state_pool;
use common::gateway::{GatewayBuilder, SERVICE_TOKEN, SERVICE_YAML, offline_state};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::json;
use tower::ServiceExt;

const DISPATCH_TOKEN: &str =
    "dbmcp_svc_8888888888888888888888888888888888888888888888888888888888888888";
const DISPATCH_SUB: &str = "service:metrics-bot";
const DISPATCH_YAML: &str = "servers: []
permissions:
  - group: svc-metrics
    grants: []
service_accounts:
  - name: metrics-bot
    group: svc-metrics
    token: dbmcp_svc_8888888888888888888888888888888888888888888888888888888888888888
";

/// Label names that would put a user, a query or a request into a series.
const FORBIDDEN_LABELS: &[&str] = &[
    "user",
    "user_sub",
    "sub",
    "email",
    "sql",
    "query",
    "request_id",
    "token",
];

fn router() -> axum::Router {
    transport::router(
        &Config::default(),
        offline_state("http://localhost:8443", SERVICE_YAML),
    )
    .expect("router builds")
}

async fn send(request: Request<Body>) -> StatusCode {
    router().oneshot(request).await.expect("response").status()
}

#[tokio::test]
async fn public_listener_does_not_serve_metrics() {
    let status = send(
        Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn request_path_series_carry_no_identity_or_sql_labels() {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("install Prometheus recorder");

    let calls = [
        Request::builder().uri("/healthz").body(Body::empty()),
        Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            )),
        Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {SERVICE_TOKEN}"))
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            )),
    ];
    for call in calls {
        send(call.expect("request")).await;
    }
    // A real audited tool dispatch, so the per-call series exist to inspect.
    let pool = state_pool().await;
    let gw = GatewayBuilder::new(DISPATCH_YAML).spawn(pool.clone()).await;
    let dispatched = reqwest::Client::new()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(DISPATCH_TOKEN)
        .json(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "list_servers"}}))
        .send()
        .await
        .expect("gateway reachable");
    assert_eq!(dispatched.status(), 200);
    assert_audit_outcome(
        &pool,
        DISPATCH_SUB,
        "list_servers",
        "success",
        "list_servers",
    )
    .await;
    delete_audit_calls(&pool, DISPATCH_SUB).await;

    let body = handle.render();
    assert!(
        body.lines().any(|line| line.starts_with("tool_calls")
            && line.contains(r#"tool="list_servers""#)
            && line.contains(r#"outcome="success""#)),
        "the dispatch left no `tool_calls` series:\n{body}"
    );
    for line in body.lines().filter(|l| !l.starts_with('#')) {
        let Some(labels) = line
            .split_once('{')
            .and_then(|(_, rest)| rest.split_once('}'))
        else {
            continue;
        };
        for pair in labels.0.split(',') {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            assert!(
                !FORBIDDEN_LABELS.contains(&name),
                "forbidden label `{name}` in: {line}"
            );
        }
    }
    for token in [SERVICE_TOKEN, DISPATCH_TOKEN] {
        assert!(!body.contains(token), "bearer leaked into metrics:\n{body}");
    }
    assert!(
        !body.contains(DISPATCH_SUB),
        "identity leaked into a label value:\n{body}"
    );
}
