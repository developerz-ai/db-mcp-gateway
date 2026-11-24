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

/// `(name, label names)` of every sample line, `_bucket`/`_sum`/`_count`
/// folded into the histogram's name and `le` dropped.
pub(super) fn rendered_series(body: &str) -> Vec<(String, Vec<String>)> {
    body.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let head = line.split_whitespace().next().expect("sample name");
            let (name, labels) = head.split_once('{').unwrap_or((head, "}"));
            let name = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|suffix| name.strip_suffix(suffix))
                .filter(|base| catalogue::CATALOGUE.iter().any(|m| m.name == *base))
                .unwrap_or(name);
            let labels = labels
                .trim_end_matches('}')
                .split(',')
                .filter_map(|pair| pair.split_once('=').map(|(k, _)| k.to_owned()))
                .filter(|k| k != "le")
                .collect();
            (name.to_owned(), labels)
        })
        .collect()
}

pub(super) const ONE_DB: &str = "servers:
  - name: pg
    kind: postgres
    host: localhost
    port: 5432
    databases:
      - name: app
        role: app_ro
        password: unused
        write_role: app_rw
        write_password: unused
permissions: []
";

#[test]
fn boot_exports_the_catalogue_with_its_label_sets_at_zero() {
    let recorder = builder().expect("builder").build_recorder();
    let config = db_mcp_gateway::config::ConfigFile::from_yaml_str(ONE_DB).expect("config parses");
    metrics::with_local_recorder(&recorder, || {
        register_boot_series();
        preregister::register_targets(&config);
    });
    let body = recorder.handle().render();
    let series = rendered_series(&body);

    for (name, labels) in &series {
        let metric = catalogue::CATALOGUE
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("`{name}` is exported but not catalogued"));
        assert_eq!(labels, metric.labels, "`{name}` label set");
    }
    for metric in catalogue::CATALOGUE {
        if metric.kind == catalogue::Kind::Counter {
            assert!(
                series.iter().any(|(name, _)| name == metric.name),
                "counter `{}` not pre-registered:\n{body}",
                metric.name
            );
        }
    }
    for sample in [
        r#"tool_calls{tool="run_query",outcome="audit_unavailable",access="write"} 0"#,
        r#"tool_calls{tool="list_servers",outcome="cancelled",access="unknown"} 0"#,
        r#"tool_calls_by_db{db="pg/app",outcome="forbidden",access="read"} 0"#,
        r#"tool_calls_by_db{db="pg/app",outcome="success",access="write"} 0"#,
        r#"handler_panics_total{layer="tool_work"} 0"#,
        r#"requests_shed_total{scope="oauth"} 0"#,
    ] {
        assert!(body.contains(sample), "missing `{sample}`:\n{body}");
    }
    assert!(
        !body.contains(r#"tool_calls{tool="list_servers",outcome="success",access="write"}"#),
        "write series registered for a read-only tool"
    );
    assert!(
        body.contains("# HELP tool_calls "),
        "catalogue not described"
    );
    assert!(
        body.contains(&format!(
            r#"build_info{{version="{}",git_sha="#,
            env!("CARGO_PKG_VERSION")
        )),
        "build_info missing:\n{body}"
    );
    assert!(
        body.contains("process_start_time_seconds "),
        "process_start_time_seconds missing:\n{body}"
    );
    preregister::exhaustive(db_mcp_gateway::audit::OutcomeCode::Success);
}

#[test]
fn catalogue_names_are_unique() {
    let mut names: Vec<_> = catalogue::CATALOGUE.iter().map(|m| m.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "duplicate catalogue entry");
}

/// O3: a gauge set once is gone from the scrape after the idle timeout; a
/// held one is re-set and stays. Scaled time: a 300 ms idle window against
/// a 50 ms refresh stands in for the shipped 1 h against 60 s.
#[tokio::test]
async fn held_gauges_outlive_the_idle_window() {
    assert!(held::REFRESH_EVERY * 4 < IDLE_TIMEOUT);
    let idle = Duration::from_millis(300);
    let recorder = builder_with_idle_timeout(idle)
        .expect("builder")
        .build_recorder();
    let held = held::HeldGauges::default();
    let _guard = metrics::set_default_local_recorder(&recorder);
    held.set("audit_pruner_last_success_timestamp", Vec::new(), 42.0);
    held.set_info("config_info", vec![("hash", "aaaa".to_owned())]);
    held.set_info("config_info", vec![("hash", "bbbb".to_owned())]);
    metrics::gauge!("tls_cert_not_after_timestamp").set(7.0);
    // The recorder times idleness from the first scrape that sees a value.
    let _first_scrape = recorder.handle().render();

    let shutdown = CancellationToken::new();
    let refreshing = held::run_refresher(&held, Duration::from_millis(50), shutdown.clone());
    let _ = tokio::time::timeout(idle * 3, refreshing).await;

    let body = recorder.handle().render();
    assert!(
        body.contains("audit_pruner_last_success_timestamp 42"),
        "held gauge lapsed:\n{body}"
    );
    assert!(body.contains(r#"config_info{hash="bbbb"} 1"#), "{body}");
    assert!(
        !body.contains(r#"hash="aaaa""#),
        "replaced info series still held:\n{body}"
    );
    assert!(
        !body.contains("tls_cert_not_after_timestamp"),
        "an unheld gauge should idle out:\n{body}"
    );
}

#[tokio::test]
async fn metrics_listener_answers_probes_before_boot_completes() {
    let recorder = builder().expect("builder").build_recorder();
    let probe: &'static probes::ProbeState = Box::leak(Box::default());
    let shutdown = CancellationToken::new();
    let addr = spawn_listener_with(
        "127.0.0.1:0".parse().expect("addr"),
        recorder.handle(),
        probe,
        shutdown.clone(),
    )
    .await
    .expect("bind");

    let healthz = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .expect("healthz");
    assert_eq!(healthz.status(), reqwest::StatusCode::OK);
    let readyz = reqwest::get(format!("http://{addr}/readyz"))
        .await
        .expect("readyz");
    assert_eq!(readyz.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(readyz.text().await.expect("body"), "starting");
    shutdown.cancel();
}
