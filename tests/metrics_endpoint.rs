//! Integration test for #13's acceptance: `curl /metrics` returns valid
//! Prometheus text exposition, and a counter recorded via the global
//! `metrics::counter!` macro shows up in the rendered body.
//!
//! In its own test binary so the process-wide `install_recorder()` doesn't
//! collide with any other test that might install one in the future.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use db_mcp_gateway::transport::AppState;
use db_mcp_gateway::transport::probes;
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;

const MAX_BODY_BYTES: usize = 1024 * 1024;

#[tokio::test]
async fn metrics_endpoint_renders_emitted_counters() {
    // Install once for this test binary. `install_recorder` would also work
    // standalone — guarding it lets the test file grow more tests later
    // without flaking on the second install.
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("install Prometheus recorder");

    // Emit a probe metric so we have something deterministic to look for.
    counter!("tool_calls", "tool" => "list_servers", "outcome" => "success").increment(1);

    let mut state = AppState::for_tests();
    state.metrics = Some(handle);
    let app = Router::new()
        .route("/metrics", get(probes::metrics))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );

    let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).expect("metrics body is UTF-8");

    // Prometheus exposition: at least one HELP/TYPE pair and a metric sample
    // line. We don't need a full parser — the line shape is enough to
    // distinguish a real render from an empty body or panic stub.
    assert!(
        body.contains("# TYPE tool_calls"),
        "missing TYPE line for tool_calls; body was:\n{body}"
    );
    assert!(
        body.contains(r#"tool_calls{outcome="success",tool="list_servers"}"#)
            || body.contains(r#"tool_calls{tool="list_servers",outcome="success"}"#),
        "missing sample line for tool_calls; body was:\n{body}"
    );
}
