//! Benchmark harness for db-mcp-gateway.
//!
//! Measures one thing well: how much latency the gateway adds over talking to
//! the same database directly, from the same host, at the same moment.
//!
//! Run order is **baseline, gateway, baseline again**. The second baseline is
//! not redundant — comparing it to the first is the only evidence we have that
//! the machine held still while the gateway ran. Without it, a background job
//! starting mid-run is indistinguishable from gateway overhead.
//!
//! Not measured here, deliberately: absolute throughput ceilings and
//! horizontal scaling. Both require the load generator to live on a different
//! machine than the gateway and the database. On one host they measure how the
//! three processes divide the CPU, which is not a fact about the gateway. See
//! `benchmarks/README.md`.

mod direct;
mod driver;
mod env;
mod gateway;
mod report;
mod stats;
mod workload;

use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;

use driver::{Path, Plan};
use workload::Shape;

#[derive(Parser, Debug)]
#[command(
    name = "bench-harness",
    about = "Measure db-mcp-gateway query overhead"
)]
struct Cli {
    /// Base URL of a running gateway, e.g. http://127.0.0.1:8443
    #[arg(long, env = "BENCH_GATEWAY_URL")]
    gateway_url: String,

    /// Service-account bearer token (`dbmcp_svc_…`). Passed by env from the
    /// wrapper script so it never lands in shell history or a process listing.
    #[arg(long, env = "BENCH_SERVICE_TOKEN", hide_env_values = true)]
    service_token: String,

    /// Postgres URL for the direct baseline — the same database the gateway
    /// is configured to reach.
    #[arg(long, env = "BENCH_DIRECT_URL", hide_env_values = true)]
    direct_url: String,

    #[arg(long, default_value = "target")]
    server: String,

    #[arg(long, default_value = "app")]
    database: String,

    #[arg(long, default_value = "/mcp")]
    mcp_path: String,

    /// Measured requests per path, per shape.
    #[arg(long, default_value_t = 2000)]
    queries: u64,

    /// Concurrent in-flight requests.
    #[arg(long, default_value_t = 8)]
    concurrent: u32,

    /// Requests discarded before measuring.
    #[arg(long, default_value_t = 200)]
    warmup: u64,

    /// Where to write the JSON result.
    #[arg(long, default_value = "benchmarks/results/latest.json")]
    out: std::path::PathBuf,
}

#[async_trait]
impl Path for gateway::GatewayClient {
    async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, String> {
        gateway::GatewayClient::run(self, shape, iteration)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &'static str {
        "gateway"
    }
}

#[async_trait]
impl Path for direct::DirectClient {
    async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, String> {
        direct::DirectClient::run(self, shape, iteration)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &'static str {
        "direct"
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let plan = Plan {
        concurrency: cli.concurrent,
        requests: cli.queries,
        warmup: cli.warmup,
    };

    let direct = Arc::new(direct::DirectClient::connect(&cli.direct_url, cli.concurrent).await?);
    eprintln!("seeding {} rows…", workload::SEED_ROWS);
    direct.seed().await?;

    let gw = Arc::new(gateway::GatewayClient::new(
        &cli.gateway_url,
        &cli.mcp_path,
        cli.service_token.clone(),
        cli.server.clone(),
        cli.database.clone(),
    )?);

    let environment = env::Environment::capture();
    if let Some(steal) = environment.cpu_steal_pct_since_boot {
        if steal > 1.0 {
            eprintln!(
                "WARNING: {steal:.2}% CPU steal since boot — this host shares cycles \
                 with other tenants and its percentiles describe them too."
            );
        }
    }
    if environment.git_dirty {
        eprintln!("WARNING: working tree is dirty; the recorded commit does not identify this run");
    }

    let mut measurements = Vec::new();

    for &shape in Shape::all() {
        eprintln!("── {} ── {}", shape.name(), shape.description());

        // Baseline, gateway, baseline again. See the module comment.
        eprint!("  direct (1/2)… ");
        let base_first = driver::run_phase(direct.clone() as Arc<dyn Path>, shape, plan)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("p50 {:.3}ms", base_first.summary.p50_ms);

        eprint!("  gateway…      ");
        let measured = driver::run_phase(gw.clone() as Arc<dyn Path>, shape, plan)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("p50 {:.3}ms", measured.summary.p50_ms);

        eprint!("  direct (2/2)… ");
        let base_second = driver::run_phase(direct.clone() as Arc<dyn Path>, shape, plan)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("p50 {:.3}ms", base_second.summary.p50_ms);

        let drift = driver::drift_pct(&base_first.summary, &base_second.summary);
        if drift > 5.0 {
            eprintln!(
                "  WARNING: baseline drifted {drift:.1}% between runs — the host did not \
                 hold still, treat this shape's delta as indicative only"
            );
        }

        measurements.push(report::Measurement::new(
            shape,
            plan,
            base_first,
            measured,
            base_second,
            drift,
        ));
    }

    direct.close().await;

    let report = report::Report::new(environment, measurements);
    report.write(&cli.out)?;
    println!("{}", report.markdown());
    eprintln!("raw results → {}", cli.out.display());

    Ok(())
}
