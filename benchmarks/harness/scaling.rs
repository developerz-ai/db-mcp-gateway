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

/// Spread the requests across the gateway instances.
///
/// Routing is **per request**, not per worker: each iteration `i` goes to
/// instance `i % n` (see [`RoundRobinPath`]). With one worker and several
/// instances that still visits every instance — successive requests walk the
/// list — and with several workers the shared iteration counter interleaves
/// the workers' requests across the list, so no worker is pinned to an
/// instance and no instance's latency distribution is worker-local. There is
/// no load balancer in the harness — the point is to drive the instances, and
/// the operator's balancer is a different system with its own overhead.
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
    use serde_json::json;

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

    /// A stand-in gateway endpoint: records the JSON-RPC id of every
    /// tools/call it receives, so the production routing path can be
    /// observed — which instance received which iteration — without a real
    /// gateway fleet. The response is a valid `run_query` envelope so the
    /// client accepts it.
    struct RecordingEndpoint {
        base_url: String,
        seen_ids: Arc<std::sync::Mutex<Vec<u64>>>,
    }

    impl RecordingEndpoint {
        async fn start() -> Self {
            let seen_ids = Arc::new(std::sync::Mutex::new(Vec::new()));
            let app = axum::Router::new().route(
                "/mcp",
                axum::routing::post({
                    let seen_ids = Arc::clone(&seen_ids);
                    move |body: String| {
                        let seen_ids = Arc::clone(&seen_ids);
                        async move {
                            let id = serde_json::from_str::<serde_json::Value>(&body)
                                .ok()
                                .and_then(|envelope| envelope["id"].as_u64())
                                .unwrap_or(u64::MAX);
                            if let Ok(mut seen) = seen_ids.lock() {
                                seen.push(id);
                            }
                            axum::Json(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {"content": [{"type": "text",
                                    "text": "{\"rows\":[[1]],\"truncated\":false}"}]}
                            }))
                        }
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            RecordingEndpoint {
                base_url: format!("http://{addr}"),
                seen_ids,
            }
        }

        /// The ids this endpoint received, sorted.
        fn received_ids(&self) -> Vec<u64> {
            let mut ids = self
                .seen_ids
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default();
            ids.sort_unstable();
            ids
        }
    }

    /// The round-robin must spread the load across every instance — a curve
    /// that quietly drove only the first instance would measure one gateway
    /// and call it N.
    ///
    /// Driven through `RoundRobinPath::run` itself, against instrumented
    /// endpoints: the assertion is which instance *received* each iteration,
    /// not a re-computation of the routing arithmetic. A routing change that
    /// sent everything to instance zero — or shifted the modulo — cannot
    /// pass this.
    #[tokio::test]
    async fn the_round_robin_spans_every_instance() {
        let mut endpoints = Vec::new();
        for _ in 0..3 {
            endpoints.push(RecordingEndpoint::start().await);
        }
        let urls: Vec<String> = endpoints.iter().map(|e| e.base_url.clone()).collect();
        let path = round_robin(build_clients(&urls, &setup(&urls)).expect("clients build"));
        assert_eq!(path.label(), "gateway-scaling");

        for iteration in 0..9u64 {
            path.run(Shape::PointLookup, iteration)
                .await
                .expect("the instrumented endpoint answered");
        }

        // Instance k must have received exactly the iterations that route
        // to it: k, k+3, k+6.
        for (instance, endpoint) in endpoints.iter().enumerate() {
            let expected: Vec<u64> = (0..9u64).filter(|i| i % 3 == instance as u64).collect();
            assert_eq!(
                endpoint.received_ids(),
                expected,
                "instance {instance} received the wrong iterations"
            );
        }
    }
}
