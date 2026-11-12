//! `/metrics` exposure (plan 101 slice 11 step 5): the scrape endpoint lives
//! on its own `METRICS_BIND` listener (src/startup/metrics.rs, unit-tested
//! there with its buckets), so the public router must not serve it — and no
//! series emitted on the request path may carry an identity or SQL label.
//!
//! Own test binary: the recorder install is process-global.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::gateway::{SERVICE_TOKEN, SERVICE_YAML, offline_state};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;

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

    let body = handle.render();
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
    assert!(
        !body.contains(SERVICE_TOKEN),
        "bearer leaked into metrics:\n{body}"
    );
}
