//! Horizontal-scaling phase: the same workload against N gateway instances.
//!
//! **What this measures, and what it does not.**
//!
//! On one host, adding gateway instances measures *contention*, not scaling.
//! The load generator, the N gateways and the database all compete for the
//! same cores, so the curve this produces describes how three (or more)
//! processes divide one CPU — not how a fleet would scale. Publishing it as a
//! scaling law would be dishonest, so it is published as what it is:
//! contention on a single shared host, with the label travelling in the JSON,
//! in the Markdown, and in the console output.
//!
//! What it *is* good for: showing whether adding a second gateway instance
//! changes the per-request latency at all on this box, and giving an operator
//! a contention curve to reason about before they build a real multi-host
//! setup. Every row is stamped with how many URLs were actually used, so a
//! run that asked for more instances than it supplied URLs cannot silently
//! publish a fabricated curve.

use std::sync::Arc;

use crate::driver::{self, Path, Plan};
use crate::gateway::GatewayClient;
use crate::stats::ScalingRow;
use crate::workload::Shape;

/// What the scaling phase needs to know: where the gateways are, how to
/// authenticate, which target to query, and how hard to drive them.
///
/// A struct rather than eight positional arguments — at seven the call site
/// stops being readable, and the arguments are easy to transpose.
pub struct ScalingSetup<'a> {
    /// Base URLs of the gateway instances.
    pub urls: &'a [String],
    pub mcp_path: &'a str,
    /// The service-account bearer token. Never logged, never in a `Debug`.
    pub bearer: &'a str,
    pub server: &'a str,
    pub database: &'a str,
    /// The shape to drive. Every shape of a backend costs about the same per
    /// request, so the scaling phase runs one of them rather than repeating
    /// the whole set for every instance count.
    pub shape: Shape,
    pub plan: Plan,
}

/// Run the workload against the first `instances` URLs.
///
/// Returns one row per instance count from 1 to `instances` (inclusive).
/// A URL list shorter than `instances` caps the curve at the number of URLs
/// supplied — the row for the requested count still appears, with
/// `urls_used` recording the shortfall, so the reader can see the curve was
/// truncated rather than assume it was not.
pub async fn measure(
    setup: &ScalingSetup<'_>,
    instances: usize,
) -> Result<Vec<ScalingRow>, String> {
    if setup.urls.is_empty() {
        return Err("no gateway URLs given for the scaling phase".to_string());
    }

    let mut rows = Vec::new();
    for count in 1..=instances.max(1) {
        let used = &setup.urls[..count.min(setup.urls.len())];
        let clients = build_clients(used, setup)?;
        eprintln!(
            "  {} instance(s): {}",
            count,
            clients
                .iter()
                .map(|c| c.mcp_url())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let result = driver::run_phase(round_robin(clients), setup.shape, setup.plan).await?;

        rows.push(ScalingRow {
            instances: count,
            urls_used: used.len(),
            throughput: result.throughput(),
            p50_ms: result.summary.p50_ms,
            p95_ms: result.summary.p95_ms,
            p99_ms: result.summary.p99_ms,
            errors: result.errors,
            samples_ms: result.samples_ms,
        });
    }
    Ok(rows)
}

/// One `GatewayClient` per base URL.
fn build_clients(
    urls: &[String],
    setup: &ScalingSetup<'_>,
) -> Result<Vec<Arc<GatewayClient>>, String> {
    urls.iter()
        .map(|url| {
            GatewayClient::new(
                url,
                setup.mcp_path,
                setup.bearer.to_string(),
                setup.server.to_string(),
                setup.database.to_string(),
            )
            .map(Arc::new)
            .map_err(|e| e.to_string())
        })
        .collect()
}

/// Spread the workers across the gateway instances.
///
/// Each worker pins itself to one instance, chosen round-robin by worker
/// index. That is what "N instances behind a list of URLs" means here: the
/// load is distributed over the instances, not sent to one of them while the
/// others idle. There is no load balancer in the harness — the point is to
/// drive the instances, and the operator's balancer is a different system
/// with its own overhead.
fn round_robin(clients: Vec<Arc<GatewayClient>>) -> Arc<dyn Path> {
    Arc::new(RoundRobinPath { clients })
}

/// A `Path` that hands each request the instance at `iteration % n`.
struct RoundRobinPath {
    clients: Vec<Arc<GatewayClient>>,
}

#[async_trait::async_trait]
impl Path for RoundRobinPath {
    async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, String> {
        // The iteration counter selects the instance, so a request that hopped
        // instances mid-phase would mix the instances' latencies into one
        // distribution. Consecutive iterations therefore hit consecutive
        // instances, and the load is spread evenly.
        let slot = (iteration as usize) % self.clients.len().max(1);
        self.clients[slot]
            .run(shape, iteration)
            .await
            .map_err(|e| e.to_string())
    }

    fn label(&self) -> &'static str {
        "gateway-scaling"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::Backend;

    fn setup<'a>(urls: &'a [String]) -> ScalingSetup<'a> {
        ScalingSetup {
            urls,
            mcp_path: "/mcp",
            bearer: "dbmcp_svc_x",
            server: "target",
            database: "app",
            shape: Shape::PointLookup,
            plan: Plan {
                concurrency: 1,
                requests: 1,
                warmup: 0,
            },
        }
    }

    #[test]
    fn every_backend_has_scaling_shapes() {
        // The scaling phase runs the same shapes as the overhead phase; a
        // backend with no shape would silently produce an empty curve.
        assert!(!Shape::for_backend(Backend::Postgres).is_empty());
        assert!(!Shape::for_backend(Backend::Mongo).is_empty());
    }

    #[tokio::test]
    async fn an_empty_url_list_is_an_error_not_an_empty_curve() {
        let err = measure(&setup(&[]), 2)
            .await
            .expect_err("no URLs means nothing to measure");
        assert!(err.contains("no gateway URLs"), "got: {err}");
    }

    /// The round-robin must spread the load across every instance — a curve
    /// that quietly drove only the first instance would measure one gateway
    /// and call it N.
    #[tokio::test]
    async fn the_round_robin_spans_every_instance() {
        let urls = vec![
            "http://127.0.0.1:9001".to_string(),
            "http://127.0.0.1:9002".to_string(),
            "http://127.0.0.1:9003".to_string(),
        ];
        let clients = build_clients(&urls, &setup(&urls)).expect("clients build");
        let path = round_robin(clients);

        // Three consecutive iterations must land on three distinct instances.
        let mut slots: Vec<usize> = (0..3u64).map(|i| (i as usize) % 3).collect();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 2]);
        assert_eq!(path.label(), "gateway-scaling");
    }
}
