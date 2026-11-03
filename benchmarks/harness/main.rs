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
//! Four phases, each of which can be run on its own:
//!
//! 1. **Overhead** — the baseline→gateway→baseline comparison, per query
//!    shape, for one backend (Postgres or MongoDB).
//! 2. **Throughput + resource use** — the same phase, additionally reporting
//!    completed requests per second and what the gateway process consumed
//!    while the phase ran.
//! 3. **Horizontal scaling** — the same workload against N gateway instances.
//!    On one host this measures *contention*, not scaling, and the result is
//!    labelled as such wherever it appears.
//! 4. **MySQL rejection** — the verification that a MySQL query target is
//!    refused at boot. It is not a latency measurement and is reported in its
//!    own section.

mod direct;
mod driver;
mod env;
mod gateway;
mod mongo;
mod mysql_reject;
mod report;
mod scaling;
mod stats;
mod workload;

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use clap::Parser;

use driver::{Path, Plan};
use report::{EffectiveConfig, ShapeRowLimit};
use stats::ScalingRow;
use workload::{Backend, Shape};

/// A string that refuses to reveal itself in `Debug` output.
///
/// `Cli` derives `Debug` (clap needs it for `--help` diagnostics), and any
/// `{:?}` of a struct containing a bare `String` for `service_token` or the
/// password-bearing `direct_url` would print the credential verbatim. `FromStr`
/// is what clap uses to parse an `#[arg]` field, so this newtype drops in
/// without an explicit `value_parser`.
#[derive(Clone)]
struct Redacted(String);

impl Redacted {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl FromStr for Redacted {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"<redacted>\"")
    }
}

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
    service_token: Redacted,

    /// Postgres URL for the direct baseline — the same database the gateway
    /// is configured to reach. Redacted in `Debug` because the DSN carries a
    /// password.
    #[arg(long, env = "BENCH_DIRECT_URL", hide_env_values = true)]
    direct_url: Redacted,

    #[arg(long, default_value = "target")]
    server: String,

    #[arg(long, default_value = "app")]
    database: String,

    #[arg(long, default_value = "/mcp")]
    mcp_path: String,

    /// Which target backend to measure. `postgres` or `mongo`.
    #[arg(
        long,
        default_value = "postgres",
        value_parser = parse_backend,
        help = "Which target backend to measure (one of: postgres, mongo)"
    )]
    backend: Backend,

    /// MongoDB URL for the direct baseline — the same database the gateway is
    /// configured to reach. Redacted in `Debug` because the URI carries a
    /// password.
    #[arg(long, env = "BENCH_MONGO_DIRECT_URL", hide_env_values = true)]
    mongo_direct_url: Option<Redacted>,

    /// MongoDB database name for the direct baseline.
    #[arg(long, default_value = "app")]
    mongo_database: String,

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

    /// How many gateway instances to drive in the horizontal-scaling phase.
    /// The phase runs with 1..=N instances; each row records how many base
    /// URLs were actually used.
    #[arg(long, default_value_t = 1)]
    instances: usize,

    /// Comma-separated gateway base URLs for the horizontal-scaling phase.
    /// The first URL is also the one the overhead phase drives.
    #[arg(long)]
    gateway_url_list: Option<String>,

    /// YAML declaring a MySQL query target. Loaded through the gateway's own
    /// config loader to verify the boot-time rejection.
    #[arg(long)]
    mysql_rejection_config: Option<std::path::PathBuf>,

    /// Interval between `/proc` samples of the gateway process, in
    /// milliseconds. `0` disables resource sampling.
    #[arg(long, default_value_t = 100)]
    resource_sample_ms: u64,
}

/// Clap value parser for `--backend`.
fn parse_backend(raw: &str) -> Result<Backend, String> {
    Backend::parse(raw).ok_or_else(|| {
        let valid = Backend::all()
            .iter()
            .map(|b| b.name())
            .collect::<Vec<_>>()
            .join(", ");
        format!("unknown backend `{raw}` — expected one of: {valid}")
    })
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

/// The direct baseline, whichever backend is being measured.
enum Baseline {
    Postgres(direct::DirectClient),
    Mongo(mongo::MongoDirectClient),
}

#[async_trait]
impl Path for Baseline {
    async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, String> {
        match self {
            Baseline::Postgres(client) => direct::DirectClient::run(client, shape, iteration)
                .await
                .map_err(|e| e.to_string()),
            Baseline::Mongo(client) => mongo::MongoDirectClient::run(client, shape, iteration)
                .await
                .map_err(|e| e.to_string()),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Baseline::Postgres(_) => "direct",
            Baseline::Mongo(_) => "direct-mongo",
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // The two paths must query the same database, or the comparison is not a
    // comparison: the gateway path would measure one dataset and the direct
    // baseline another. Caught before any request is issued, because a
    // mismatch discovered halfway through a run wastes the whole run.
    check_paths_query_the_same_database(&cli)?;

    let plan = Plan {
        concurrency: cli.concurrent,
        requests: cli.queries,
        warmup: cli.warmup,
    };

    // The gateway processes' PIDs, for the resource sampler. The runner
    // script launches the gateway and the harness together, so the PIDs
    // arrive in the environment.
    let gateway_pids = gateway_pids();

    let baseline = Arc::new(connect_baseline(&cli).await?);
    seed_baseline(&baseline).await?;

    // One gateway client for the whole run: one HTTP connection pool, one
    // bearer, one target server/database. The resource sampler needs a
    // distinct handle per phase only for the sampler, not for the client.
    let gw = Arc::new(gateway::GatewayClient::new(
        &cli.gateway_url,
        &cli.mcp_path,
        cli.service_token.expose().to_string(),
        cli.server.clone(),
        cli.database.clone(),
    )?);

    let environment = env::Environment::capture();
    if let Some(steal) = environment.cpu_steal_pct_since_boot
        && steal > 1.0
    {
        eprintln!(
            "WARNING: {steal:.2}% CPU steal since boot — this host shares cycles \
             with other tenants and its percentiles describe them too."
        );
    }
    if environment.git_dirty {
        eprintln!("WARNING: working tree is dirty; the recorded commit does not identify this run");
    }

    let mut measurements = Vec::new();

    for shape in Shape::for_backend(cli.backend) {
        eprintln!("── {} ── {}", shape.name(), shape.description());

        // Baseline, gateway, baseline again. See the module comment.
        eprint!("  direct (1/2)… ");
        let base_first = driver::run_phase(Arc::clone(&baseline) as Arc<dyn Path>, shape, plan)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("p50 {:.3}ms", base_first.summary.p50_ms);
        eprint!("  gateway…      ");
        let (measured, resources) =
            run_gateway_phase(&cli, &gw, &gateway_pids, shape, plan).await?;
        eprintln!("p50 {:.3}ms", measured.summary.p50_ms);

        eprint!("  direct (2/2)… ");
        let base_second = driver::run_phase(Arc::clone(&baseline) as Arc<dyn Path>, shape, plan)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("p50 {:.3}ms", base_second.summary.p50_ms);

        let drift = driver::drift_pct(&base_first.summary, &base_second.summary);
        if drift > report::MAX_TRUSTED_DRIFT_PCT {
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
            resources,
        ));
    }

    close_baseline(&baseline).await;

    let effective_config = effective_config(&cli, plan);
    let mut report = report::Report::new(environment, effective_config, measurements);

    // Horizontal scaling. Contention on one host, labelled as such.
    if cli.instances > 1 {
        let urls = gateway_urls(&cli);
        eprintln!(
            "── horizontal scaling ── {} instance(s) on one host",
            cli.instances
        );
        let setup = scaling::ScalingSetup {
            urls: &urls,
            mcp_path: &cli.mcp_path,
            bearer: cli.service_token.expose(),
            server: &cli.server,
            database: &cli.database,
            shape: Shape::for_backend(cli.backend)
                .first()
                .copied()
                .unwrap_or(Shape::PointLookup),
            plan,
        };
        let rows = scaling::measure(&setup, cli.instances)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("  driving: {}", urls.join(", "));
        for row in &rows {
            eprintln!(
                "  {} instance(s): {:.0} req/s, p50 {:.2}ms",
                row.instances, row.throughput.requests_per_sec, row.p50_ms
            );
        }
        eprintln!("  ({})", ScalingRow::caveat());
        report = report.with_scaling(rows);
    }

    // MySQL rejection. Its own verdict, separate from any latency number.
    if cli.mysql_rejection_config.is_some() {
        eprintln!("── mysql rejection ──");
        let verdict = mysql_reject::verify(cli.mysql_rejection_config.as_deref());
        eprintln!(
            "  boot rejected: {}, runtime backstop: {}, verdict: {}",
            verdict.boot_rejected,
            verdict.runtime_backstop_ok,
            if verdict.passed() { "PASS" } else { "FAIL" }
        );
        report = report.with_mysql_rejection(verdict);
    }

    report.write(&cli.out)?;
    println!("{}", report.markdown());
    eprintln!("raw results → {}", cli.out.display());

    Ok(())
}

/// Open the direct baseline for the selected backend.
async fn connect_baseline(cli: &Cli) -> anyhow::Result<Baseline> {
    match cli.backend {
        Backend::Postgres => {
            let client =
                direct::DirectClient::connect(cli.direct_url.expose(), cli.concurrent).await?;
            Ok(Baseline::Postgres(client))
        }
        Backend::Mongo => {
            let url = cli
                .mongo_direct_url
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "--backend mongo requires --mongo-direct-url (the mongo baseline needs a \
                         direct connection to the same database the gateway reaches)"
                    )
                })?
                .expose()
                .to_string();
            let (host, port, user, password, auth_db) = mongo::parse_mongo_url(&url)?;
            let client = mongo::MongoDirectClient::connect(
                &host,
                port,
                &user,
                &password,
                &auth_db,
                &cli.mongo_database,
                cli.concurrent,
            )
            .await?;
            Ok(Baseline::Mongo(client))
        }
    }
}

/// Seed the benchmark data for the selected backend.
async fn seed_baseline(baseline: &Arc<Baseline>) -> anyhow::Result<()> {
    match &**baseline {
        Baseline::Postgres(client) => {
            eprintln!("seeding {} rows…", workload::SEED_ROWS);
            client.seed().await?;
        }
        Baseline::Mongo(client) => {
            eprintln!("seeding {} documents…", workload::MONGO_SEED_DOCS);
            client.seed().await?;
        }
    }
    Ok(())
}

/// Close the direct baseline.
async fn close_baseline(baseline: &Arc<Baseline>) {
    match &**baseline {
        Baseline::Postgres(client) => client.close().await,
        Baseline::Mongo(client) => client.close().await,
    }
}

/// The effective configuration of this run, for the result file.
///
/// Everything here is a value the harness applied or observed — never a
/// value copied out of the gateway's configuration file, which the harness
/// cannot read (the gateway deliberately does not expose grant constraints
/// over MCP). A reader gets the workload and the limits that were in force,
/// which is what makes the published percentiles interpretable.
fn effective_config(cli: &Cli, plan: Plan) -> EffectiveConfig {
    let shapes = Shape::for_backend(cli.backend);
    EffectiveConfig {
        backend: cli.backend.name(),
        server: cli.server.clone(),
        database: cli.database.clone(),
        direct_database: direct_database(cli),
        direct_target_host: direct_target_host(cli),
        concurrency: plan.concurrency,
        requests_per_phase: plan.requests,
        warmup: plan.warmup,
        row_limit_per_shape: shapes
            .iter()
            .map(|shape| ShapeRowLimit {
                shape: shape.name(),
                limit: shape.limit(),
            })
            .collect(),
        statement_timeout_ms: GATEWAY_CLIENT_TIMEOUT_MS,
        seed_rows: seed_rows(cli.backend),
    }
}

/// The statement timeout the harness's gateway client enforces, in
/// milliseconds.
///
/// This is the harness's own ceiling on a single request — the value the
/// client aborts at. The *database-side* `statement_timeout` is the
/// gateway's grant policy; it is not observable from outside the gateway,
/// so this report does not claim to know it.
const GATEWAY_CLIENT_TIMEOUT_MS: u64 = 30_000;

/// The database the direct baseline queries.
///
/// On the postgres path the direct client connects to the database named in
/// its URL — the URL's path segment — because that is what the server
/// resolves; on the mongo path the harness is told the database name
/// separately, and that is the one the mongo client selects.
fn direct_database(cli: &Cli) -> String {
    match cli.backend {
        Backend::Postgres => postgres_database(cli.direct_url.expose()),
        Backend::Mongo => cli.mongo_database.clone(),
    }
}

/// The database named in a postgres URL's path.
///
/// Empty when the URL names none — a URL without a database path connects to
/// the server's default, which the harness cannot know, so it reports
/// nothing rather than guessing.
fn postgres_database(url: &str) -> String {
    let Some(parsed) = url::Url::parse(url).ok() else {
        return String::new();
    };
    parsed.path().trim_matches('/').to_string()
}

/// The direct baseline's target host, for the record.
///
/// Host and port only — never the user, the password or the connection
/// string. The URL is parsed and reduced to this host before it reaches the
/// report, so a credential cannot ride along into the result file.
fn direct_target_host(cli: &Cli) -> String {
    match cli.backend {
        Backend::Postgres => postgres_host(cli.direct_url.expose()),
        Backend::Mongo => match &cli.mongo_direct_url {
            Some(url) => match mongo::parse_mongo_url(url.expose()) {
                Ok((host, port, _, _, _)) => format!("{host}:{port}"),
                Err(_) => "unknown".to_string(),
            },
            None => "unknown".to_string(),
        },
    }
}

/// The host and port of a postgres URL, with the credentials discarded.
///
/// Deliberately never returns the whole URL: this string is published in
/// the result file and the Markdown report, and a DSN carries a password.
fn postgres_host(url: &str) -> String {
    let Some(parsed) = url::Url::parse(url).ok() else {
        return "unknown".to_string();
    };
    let Some(host) = parsed.host_str() else {
        return "unknown".to_string();
    };
    match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// The number of rows (or documents) seeded into the target before the run.
fn seed_rows(backend: Backend) -> i64 {
    match backend {
        Backend::Postgres => workload::SEED_ROWS,
        Backend::Mongo => workload::MONGO_SEED_DOCS,
    }
}

/// Fail fast when the two paths would query different databases.
///
/// The gateway path is told its database by `--database`; the direct
/// baseline gets its own — the postgres URL's path segment, or
/// `--mongo-database` on the mongo path. If they disagree the run compares
/// two different datasets and the published delta means nothing — so this is
/// an error, not a warning, and it fires before the first request.
///
/// A direct target that names no database at all (the server's default) is
/// not a mismatch the harness can judge, so it is left alone rather than
/// guessed at.
fn check_paths_query_the_same_database(cli: &Cli) -> anyhow::Result<()> {
    let gateway_database = cli.database.as_str();
    let direct = direct_database(cli);
    if direct.is_empty() || gateway_database == direct {
        return Ok(());
    }
    anyhow::bail!(
        "the gateway path queries database `{gateway_database}` but the direct baseline queries \
         `{direct}` — the two paths must query the same database or the comparison is \
         meaningless"
    )
}

/// Run the gateway phase for one shape, sampling the gateway processes'
/// resources while it runs.
async fn run_gateway_phase(
    cli: &Cli,
    gw: &Arc<gateway::GatewayClient>,
    gateway_pids: &[u32],
    shape: Shape,
    plan: Plan,
) -> anyhow::Result<(driver::PhaseResult, stats::ResourceUsage)> {
    let stop = Arc::new(AtomicBool::new(false));
    // One sampler thread per gateway process. A run with several instances
    // samples each of them, so the published resource figures cover the
    // whole gateway fleet rather than one process.
    let samplers: Vec<_> = gateway_pids
        .iter()
        .map(|pid| {
            driver::ResourceSampler::new(*pid, cli.resource_sample_ms).spawn(Arc::clone(&stop))
        })
        .collect();

    let result = driver::run_phase(Arc::clone(gw) as Arc<dyn Path>, shape, plan)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    stop.store(true, Ordering::Relaxed);
    let mut usage = stats::ResourceUsage::unavailable();
    for handle in samplers {
        let Ok(sampler) = handle.join() else {
            // A panicking sampler thread must not fail the run — the latency
            // numbers are still valid; only the resource observation is lost.
            continue;
        };
        let observed = sampler.usage();
        usage.peak_rss_bytes = usage.peak_rss_bytes.max(observed.peak_rss_bytes);
        // Each instance reports the CPU it burned *during this phase* — a
        // delta from its own first sample, not its lifetime counter. Summing
        // the deltas gives the fleet's phase cost; summing lifetime CPU would
        // charge the phase for boot and every earlier phase.
        usage.cpu_seconds += observed.cpu_seconds;
        usage.samples += observed.samples;
    }

    Ok((result, usage))
}

/// The gateway processes' PIDs, for the resource sampler.
///
/// The runner script exports `BENCH_GATEWAY_PIDS` — a comma-separated list,
/// one PID per gateway instance it started. The singular `BENCH_GATEWAY_PID`
/// is accepted too, so a hand-run with one gateway is as easy as the
/// scripted run with several.
fn gateway_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    for key in ["BENCH_GATEWAY_PIDS", "BENCH_GATEWAY_PID"] {
        let Ok(raw) = std::env::var(key) else {
            continue;
        };
        for part in raw.split(',') {
            if let Ok(pid) = part.trim().parse::<u32>()
                && !pids.contains(&pid)
            {
                pids.push(pid);
            }
        }
        if !pids.is_empty() {
            break;
        }
    }
    pids
}

/// The gateway base URLs for the scaling phase.
///
/// The `--gateway-url-list` CSV, or a single-element list built from
/// `--gateway-url`. A list shorter than `--instances` caps the curve at the
/// number of URLs supplied — the row for the requested count still appears,
/// with `urls_used` recording the shortfall.
fn gateway_urls(cli: &Cli) -> Vec<String> {
    match &cli.gateway_url_list {
        Some(raw) => raw
            .split(',')
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect(),
        None => vec![cli.gateway_url.clone()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_list_is_split_on_commas_and_trimmed() {
        let cli = Cli::parse_from([
            "bench-harness",
            "--gateway-url",
            "http://127.0.0.1:9001",
            "--service-token",
            "t",
            "--direct-url",
            "postgres://x/y",
            "--gateway-url-list",
            "http://127.0.0.1:9001, http://127.0.0.1:9002 ,",
        ]);
        let urls = gateway_urls(&cli);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[1], "http://127.0.0.1:9002");
    }

    #[test]
    fn without_a_url_list_the_single_gateway_url_is_used() {
        let cli = Cli::parse_from([
            "bench-harness",
            "--gateway-url",
            "http://127.0.0.1:9001",
            "--service-token",
            "t",
            "--direct-url",
            "postgres://x/y",
        ]);
        assert_eq!(
            gateway_urls(&cli),
            vec!["http://127.0.0.1:9001".to_string()]
        );
    }

    #[test]
    fn the_backend_flag_accepts_both_dialects_and_rejects_others() {
        assert_eq!(parse_backend("postgres").expect("valid"), Backend::Postgres);
        assert_eq!(parse_backend("mongo").expect("valid"), Backend::Mongo);
        assert_eq!(parse_backend("MongoDB").expect("valid"), Backend::Mongo);
        assert!(parse_backend("mysql").is_err());
    }

    /// The default `--backend` must stay `postgres` — the existing runner
    /// script passes no backend flag and must keep measuring what it always
    /// measured.
    #[test]
    fn the_default_backend_is_postgres() {
        let cli = Cli::parse_from([
            "bench-harness",
            "--gateway-url",
            "http://127.0.0.1:9001",
            "--service-token",
            "t",
            "--direct-url",
            "postgres://x/y",
        ]);
        assert_eq!(cli.backend, Backend::Postgres);
        assert_eq!(cli.instances, 1);
        assert_eq!(cli.resource_sample_ms, 100);
    }

    /// The runner script exports a comma-separated PID list; the harness
    /// must read every PID in it, not just the first.
    #[test]
    fn gateway_pids_are_read_from_the_comma_separated_list() {
        // The env var is process-global, so the test sets and restores it
        // rather than racing another test reading the same key.
        let previous = std::env::var("BENCH_GATEWAY_PIDS").ok();
        // SAFETY: single-threaded test body; the harness reads this key once
        // at start-up, before any test runs.
        unsafe { std::env::set_var("BENCH_GATEWAY_PIDS", "1234, 5678 ,9012") };
        assert_eq!(gateway_pids(), vec![1234, 5678, 9012]);
        match previous {
            Some(value) => unsafe { std::env::set_var("BENCH_GATEWAY_PIDS", value) },
            None => unsafe { std::env::remove_var("BENCH_GATEWAY_PIDS") },
        }
    }

    fn cli_with(args: &[&str]) -> Cli {
        let mut argv = vec![
            "bench-harness",
            "--gateway-url",
            "http://127.0.0.1:9001",
            "--service-token",
            "t",
            "--direct-url",
            "postgres://app:app-dev-only@localhost:5434/app",
        ];
        argv.extend_from_slice(args);
        Cli::parse_from(argv)
    }

    /// The effective configuration must name the target the run measured —
    /// a result file that says "postgres" and nothing else cannot be
    /// interpreted.
    #[test]
    fn the_effective_configuration_names_the_measured_target() {
        let cli = cli_with(&["--server", "target", "--database", "app"]);
        let plan = Plan {
            concurrency: 8,
            requests: 2000,
            warmup: 200,
        };
        let cfg = effective_config(&cli, plan);
        assert_eq!(cfg.backend, "postgres");
        assert_eq!(cfg.server, "target");
        assert_eq!(cfg.database, "app");
        assert_eq!(cfg.direct_database, "app");
        assert_eq!(cfg.concurrency, 8);
        assert_eq!(cfg.requests_per_phase, 2000);
        assert_eq!(cfg.warmup, 200);
        assert_eq!(cfg.seed_rows, workload::SEED_ROWS);
        // Every measured shape's row cap must be recorded — that is the
        // number that decides whether a response was truncated.
        assert!(!cfg.row_limit_per_shape.is_empty());
        for entry in &cfg.row_limit_per_shape {
            assert!(entry.limit > 0, "shape {} has no row cap", entry.shape);
        }
    }

    /// The published target host must be the host only. A connection string
    /// carries a password, and this value lands in the result file and the
    /// Markdown report.
    #[test]
    fn the_direct_target_host_never_carries_the_credentials() {
        let cli = cli_with(&[]);
        let host = direct_target_host(&cli);
        assert_eq!(host, "localhost:5434");
        assert!(!host.contains("app-dev-only"), "leaked a password: {host}");
        assert!(!host.contains("app:"), "leaked the user: {host}");
    }

    /// The mongo path's target host comes from the mongo URL, and must be
    /// just as credential-free.
    #[test]
    fn the_mongo_direct_target_host_never_carries_the_credentials() {
        let cli = cli_with(&[
            "--backend",
            "mongo",
            "--mongo-direct-url",
            "mongodb://app:app-dev-only@localhost:27018/app",
        ]);
        let host = direct_target_host(&cli);
        assert_eq!(host, "localhost:27018");
        assert!(!host.contains("app-dev-only"), "leaked a password: {host}");
    }

    /// The two paths must query the same database, or the comparison is
    /// meaningless. A mismatch must fail before the first request.
    #[test]
    fn a_database_mismatch_between_the_two_paths_fails_fast() {
        let cli = cli_with(&[
            "--backend",
            "mongo",
            "--database",
            "app",
            "--mongo-database",
            "other",
            "--mongo-direct-url",
            "mongodb://app:app-dev-only@localhost:27018/app",
        ]);
        let err = check_paths_query_the_same_database(&cli)
            .expect_err("the two paths query different databases");
        assert!(
            err.to_string().contains("must query the same database"),
            "{err}"
        );
    }

    /// The matching case must pass — the guard must not fire on a correct
    /// configuration.
    #[test]
    fn matching_databases_pass_the_guard() {
        let cli = cli_with(&["--database", "app"]);
        check_paths_query_the_same_database(&cli).expect("the paths agree");
    }

    /// The postgres direct baseline takes its database from the URL's path,
    /// so `--database` disagreeing with that URL is the same class of
    /// misconfiguration and must fail the same way.
    #[test]
    fn a_postgres_database_mismatch_fails_fast() {
        let cli = cli_with(&["--database", "other"]);
        let err = check_paths_query_the_same_database(&cli)
            .expect_err("the direct URL names `app`, the gateway path names `other`");
        assert!(
            err.to_string().contains("must query the same database"),
            "{err}"
        );
    }

    /// The effective configuration must record the database the direct
    /// baseline actually queried — the URL's path segment, not whatever
    /// `--database` happens to say.
    #[test]
    fn the_effective_config_records_the_direct_baselines_database() {
        let cli = cli_with(&["--database", "app"]);
        assert_eq!(direct_database(&cli), "app");
    }
}
