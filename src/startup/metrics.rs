//! The Prometheus recorder and its own listener. `/metrics` is served on
//! `METRICS_BIND`, never on the public listener: the series name every
//! configured database, and the scrape is cluster-internal traffic. The same
//! listener answers `/healthz` and `/readyz` ([`probes`]).

pub(crate) mod catalogue;
mod cert;
pub(crate) mod held;
pub(crate) mod loaded;
pub(crate) mod preregister;
pub(crate) mod probes;
pub(crate) mod state_pools;

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use metrics_util::MetricKindMask;
use tokio_util::sync::CancellationToken;

/// Fixed buckets so the series aggregate across replicas (summaries do not).
/// Spans a fast catalog read to the slowest statement timeout.
const QUERY_DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];
/// From an idle connection handed straight over to the 5 s acquire timeout.
const POOL_ACQUIRE_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];
/// The synchronous audit insert sits on every response; resolve the low end.
const AUDIT_WRITE_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];
/// A gauge or histogram not touched for this long leaves the scrape output, so
/// an evicted database's labels do not linger forever. Counters are exempt:
/// `increase()` alerts must not see a reset because a series went quiet. A
/// live gauge never gets here: pool gauges are sampled every 15 s and the
/// rest are held ([`held`]).
const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// `install_recorder` starts no upkeep task; without one, histogram samples
/// recorded between scrapes accumulate unbounded.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The recorder configuration the gateway ships with.
fn builder() -> Result<PrometheusBuilder, BuildError> {
    builder_with_idle_timeout(IDLE_TIMEOUT)
}

fn builder_with_idle_timeout(idle: Duration) -> Result<PrometheusBuilder, BuildError> {
    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("query_duration_seconds".to_owned()),
            QUERY_DURATION_BUCKETS,
        )?
        .set_buckets_for_metric(
            Matcher::Full("audit_write_duration_seconds".to_owned()),
            AUDIT_WRITE_BUCKETS,
        )?
        .set_buckets_for_metric(
            Matcher::Full("pool_acquire_wait_seconds".to_owned()),
            POOL_ACQUIRE_BUCKETS,
        )
        .map(|b| {
            b.idle_timeout(
                MetricKindMask::GAUGE | MetricKindMask::HISTOGRAM,
                Some(idle),
            )
        })
}

/// Install the process-wide recorder, describe and pre-register the
/// catalogue, and start the upkeep and held-gauge loops.
pub(crate) fn install_recorder(shutdown: CancellationToken) -> anyhow::Result<PrometheusHandle> {
    let handle = builder()?
        .install_recorder()
        .map_err(|err| anyhow::anyhow!("failed to install Prometheus recorder: {err}"))?;
    describe_catalogue();
    preregister::register_static();
    loaded::record_build_info();
    loaded::record_process_start();
    let refresher_stop = shutdown.clone();
    tokio::spawn(async move {
        held::run_refresher(held::held(), held::REFRESH_EVERY, refresher_stop).await;
    });
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(UPKEEP_INTERVAL);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => upkeep.run_upkeep(),
            }
        }
    });
    Ok(handle)
}

/// Bind the metrics listener now (a taken port fails boot) and serve it until
/// `shutdown` fires.
pub(crate) async fn spawn_listener(
    bind: SocketAddr,
    handle: PrometheusHandle,
    shutdown: CancellationToken,
) -> anyhow::Result<SocketAddr> {
    spawn_listener_with(bind, handle, probes::probe_state(), shutdown).await
}

async fn spawn_listener_with(
    bind: SocketAddr,
    handle: PrometheusHandle,
    probe: &'static probes::ProbeState,
    shutdown: CancellationToken,
) -> anyhow::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|err| anyhow::anyhow!("failed to bind METRICS_BIND {bind}: {err}"))?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        let served = axum::serve(listener, router(handle, probe))
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await;
        if let Err(error) = served {
            tracing::error!(%error, "metrics listener stopped");
        }
    });
    tracing::info!(addr = %local, "metrics listening");
    Ok(local)
}

/// `# HELP` and `# TYPE` for every catalogued series.
fn describe_catalogue() {
    use catalogue::{CATALOGUE, Kind};
    for metric in CATALOGUE {
        match metric.kind {
            Kind::Counter => metrics::describe_counter!(metric.name, metric.help),
            Kind::Gauge => metrics::describe_gauge!(metric.name, metric.help),
            Kind::Histogram => metrics::describe_histogram!(metric.name, metric.help),
        }
    }
}

fn router(handle: PrometheusHandle, probe: &'static probes::ProbeState) -> Router {
    let probe_routes = Router::new()
        .route("/healthz", get(probes::healthz))
        .route("/readyz", get(probes::readyz))
        .with_state(probe);
    Router::new()
        .route("/metrics", get(move || render(handle.clone())))
        .merge(probe_routes)
}

async fn render(handle: PrometheusHandle) -> Response {
    let mut response = handle.render().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROM_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests;
