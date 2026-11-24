//! Target pool metrics against a real Postgres (plan 101 O3/O4): the
//! sampler publishes the pool's true state while it lives, and every acquire
//! lands in `pool_acquire_wait_seconds`.
//!
//! The recorder is thread-local (`set_default_local_recorder`) and the test
//! runtime is current-thread, so the adapter's sampler task reports into it
//! and no process-global recorder is installed.

use std::sync::Arc;
use std::time::Duration;

use db_mcp_gateway::exec::{Access, DEFAULT_POOL_MAX_CONNECTIONS, DbAdapter, ExecQuery};
use metrics_exporter_prometheus::PrometheusBuilder;
use uuid::Uuid;

use crate::common::pg_target;

/// One sampler period (15 s) plus margin: the in-use gauge moves on the
/// sample after the queries start.
const SAMPLE_DEADLINE: Duration = Duration::from_secs(25);
const BUSY_QUERIES: usize = 2;

fn sample(body: &str, series: &str) -> Option<f64> {
    body.lines()
        .find(|line| line.starts_with(series))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn pool_gauges_track_connections_in_use_under_load() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = metrics::set_default_local_recorder(&recorder);
    let adapter = Arc::new(pg_target::adapter().await);
    let db = format!(
        "{}/{}",
        pg_target::server().name,
        pg_target::database().name
    );
    let labels = format!(r#"{{db="{db}",pool_kind="query"}}"#);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let body = handle.render();
    assert_eq!(
        sample(&body, &format!("pool_size{labels}")),
        Some(f64::from(DEFAULT_POOL_MAX_CONNECTIONS)),
        "pool_size not sampled at open:\n{body}"
    );
    assert_eq!(
        sample(&body, &format!("pool_connections_in_use{labels}")),
        Some(0.0),
        "{body}"
    );

    let busy: Vec<_> = (0..BUSY_QUERIES)
        .map(|_| {
            let adapter = Arc::clone(&adapter);
            tokio::spawn(async move {
                adapter
                    .execute(ExecQuery {
                        sql: "SELECT pg_sleep(20) /* metrics-pool */",
                        binds: &[],
                        statement_timeout_ms: Some(30_000),
                        row_limit: 1,
                        access: Access::ReadOnly,
                        dry_run: false,
                        request_id: Uuid::new_v4(),
                    })
                    .await
            })
        })
        .collect();

    let deadline = tokio::time::Instant::now() + SAMPLE_DEADLINE;
    let in_use = loop {
        let body = handle.render();
        let in_use = sample(&body, &format!("pool_connections_in_use{labels}"));
        if in_use >= Some(BUSY_QUERIES as f64) || tokio::time::Instant::now() >= deadline {
            break (in_use, body);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    for task in busy {
        task.abort();
    }
    let (in_use, body) = in_use;
    assert_eq!(
        in_use,
        Some(BUSY_QUERIES as f64),
        "in-use gauge never showed the busy queries:\n{body}"
    );
    let acquires = sample(&body, &format!("pool_acquire_wait_seconds_count{labels}"));
    assert!(
        acquires >= Some(BUSY_QUERIES as f64),
        "acquires not recorded:\n{body}"
    );
    assert!(
        !body.contains(pg_target::TARGET_HOST),
        "a host reached a label"
    );
}
