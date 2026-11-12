//! Recorder configuration and the dedicated listener. The recorder is built,
//! never installed, so these tests share no process-global state.

use super::*;

fn record_both(recorder: &metrics_exporter_prometheus::PrometheusRecorder) {
    metrics::with_local_recorder(recorder, || {
        metrics::histogram!("query_duration_seconds", "tool" => "run_query").record(0.02);
        metrics::histogram!("audit_write_duration_seconds").record(0.003);
    });
}

#[test]
fn duration_histograms_render_as_buckets_not_summaries() {
    let recorder = builder().expect("builder").build_recorder();
    record_both(&recorder);

    let body = recorder.handle().render();
    assert!(
        body.contains(r#"query_duration_seconds_bucket{tool="run_query",le="0.025"} 1"#),
        "query histogram buckets missing:\n{body}"
    );
    assert!(
        body.contains(r#"audit_write_duration_seconds_bucket{le="0.005"} 1"#),
        "audit histogram buckets missing:\n{body}"
    );
    assert!(!body.contains("quantile="), "summary rendered:\n{body}");
}

#[tokio::test]
async fn listener_serves_metrics_and_stops_on_shutdown() {
    let recorder = builder().expect("builder").build_recorder();
    record_both(&recorder);
    let shutdown = CancellationToken::new();

    let addr = spawn_listener(
        "127.0.0.1:0".parse().expect("addr"),
        recorder.handle(),
        shutdown.clone(),
    )
    .await
    .expect("bind");

    let url = format!("http://{addr}/metrics");
    let response = reqwest::get(&url).await.expect("scrape");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let content_type = response.headers()[reqwest::header::CONTENT_TYPE].clone();
    assert!(
        content_type
            .to_str()
            .expect("ascii")
            .starts_with("text/plain")
    );
    assert!(
        response
            .text()
            .await
            .expect("body")
            .contains("query_duration_seconds_bucket")
    );

    shutdown.cancel();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while reqwest::get(&url).await.is_ok() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "listener still serving after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
