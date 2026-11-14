//! Result serialization: machine-readable JSON, plus the Markdown table that
//! goes into the docs.
//!
//! The Markdown is generated rather than hand-copied so a published table
//! cannot drift from the JSON beside it. Anything a reader needs to judge the
//! numbers — sample size, error count, baseline drift — is emitted alongside
//! them, not left in a log.

use std::path::Path;

use serde::Serialize;

use crate::driver::{PhaseResult, Plan};
use crate::env::Environment;
use crate::mysql_reject::MySqlRejection;
use crate::stats::{Overhead, ResourceUsage, ScalingRow, Summary, Throughput};
use crate::workload::Shape;

/// Baseline drift above this percentage means the host moved between the two
/// baseline runs, and the gateway delta measured in between is not comparable.
/// One constant so the `trustworthy()` decision, the console warning in
/// `main.rs`, and the caveat prose in the Markdown table cannot drift apart.
pub const MAX_TRUSTED_DRIFT_PCT: f64 = 5.0;

#[derive(Debug, Serialize)]
pub struct Measurement {
    pub shape: Shape,
    /// Which backend the shape ran against. On the row so a reader of the
    /// JSON never has to look the shape up in the source to know which
    /// database the numbers came from.
    pub backend: &'static str,
    pub description: &'static str,
    pub concurrency: u32,
    pub requests_per_phase: u64,
    pub direct: Summary,
    pub gateway: Summary,
    /// Second baseline run, after the gateway phase.
    pub direct_recheck: Summary,
    /// The recheck's raw per-request latencies, in global completion order.
    ///
    /// Published alongside `direct_samples_ms` and `gateway_samples_ms` so
    /// the baseline drift — and the recheck's own percentiles — can be
    /// re-derived from the result file. Discarding them would leave the
    /// drift column unauditable: a reader could check the two published
    /// baselines against each other but never either one against its own
    /// raw samples.
    pub direct_recheck_samples_ms: Vec<f64>,
    /// Difference between the two baseline runs, as a percentage of the first.
    pub baseline_drift_pct: f64,
    pub overhead: Overhead,
    pub direct_errors: u64,
    pub gateway_errors: u64,
    pub first_gateway_error: Option<String>,
    /// Completed requests per second on each path. **Not** an absolute
    /// capacity number — the load generator, the gateway and the database
    /// share one host. See [`Throughput`].
    pub direct_throughput: Throughput,
    pub gateway_throughput: Throughput,
    /// What the gateway process consumed during the measured phase.
    pub gateway_resources: ResourceUsage,
    /// The raw per-request latencies for each path, in global completion
    /// order.
    ///
    /// Published so the percentiles above can be re-derived from the result
    /// file instead of taken on trust. A `Summary` is lossy: from n, the
    /// percentiles, min, max and mean you cannot recompute p90 or the
    /// coefficient of variation, let alone confirm the numbers came from one
    /// distribution.
    ///
    /// The samples are latencies in milliseconds — no credential, query text
    /// or response body is in them.
    pub direct_samples_ms: Vec<f64>,
    pub gateway_samples_ms: Vec<f64>,
}

impl Measurement {
    pub fn new(
        shape: Shape,
        plan: Plan,
        base_first: PhaseResult,
        measured: PhaseResult,
        base_second: PhaseResult,
        drift_pct: f64,
        gateway_resources: ResourceUsage,
    ) -> Self {
        let overhead = Overhead::between(&base_first.summary, &measured.summary);
        Measurement {
            shape,
            backend: shape.backend().name(),
            description: shape.description(),
            concurrency: plan.concurrency,
            requests_per_phase: plan.requests,
            direct_throughput: base_first.throughput(),
            gateway_throughput: measured.throughput(),
            direct: base_first.summary,
            gateway: measured.summary,
            direct_recheck: base_second.summary,
            direct_recheck_samples_ms: base_second.samples_ms,
            baseline_drift_pct: drift_pct,
            overhead,
            direct_errors: base_first.errors,
            gateway_errors: measured.errors,
            first_gateway_error: measured.first_error,
            gateway_resources,
            direct_samples_ms: base_first.samples_ms,
            gateway_samples_ms: measured.samples_ms,
        }
    }

    /// Whether this row is solid enough to publish without a caveat.
    fn trustworthy(&self) -> bool {
        self.baseline_drift_pct <= MAX_TRUSTED_DRIFT_PCT
            && self.gateway_errors == 0
            && self.direct_errors == 0
    }
}

/// The effective configuration of one benchmark run.
///
/// A latency number without the configuration that produced it is not a
/// measurement, it is a rumour. This section travels in the result file
/// beside the numbers so a reader can tell *which* database, *which* grants
/// and *which* workload produced them — without having to reconstruct the
/// run from the command line.
///
/// Every field here is something the harness actually applied or observed.
/// Nothing is copied from the gateway's configuration file: the harness
/// cannot read the operator's grants (the gateway deliberately does not
/// expose grant constraints over MCP), so it publishes the request-side
/// values it knows — the row cap it asked for and the timeout it enforced —
/// rather than inventing grant values it never saw.
#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfig {
    /// The backend measured: `postgres` or `mongo`.
    pub backend: &'static str,
    /// The gateway-side server name the measured requests addressed.
    pub server: String,
    /// The gateway-side database name the measured requests addressed.
    pub database: String,
    /// The database the direct baseline queried. Equal to `database` on the
    /// postgres path; on the mongo path it is the harness's own
    /// `--mongo-database`, because the mongo baseline connects to the
    /// database directly rather than through the gateway's server/database
    /// pair.
    pub direct_database: String,
    /// The direct baseline's target host, taken from the connection URL.
    ///
    /// Host only — never the port's credentials, never the DSN. The URL is
    /// parsed and reduced to this string before it reaches the report.
    pub direct_target_host: String,
    /// Concurrent in-flight requests.
    pub concurrency: u32,
    /// Measured requests per path, per shape.
    pub requests_per_phase: u64,
    /// Requests discarded before measuring.
    pub warmup: u64,
    /// The row cap the harness asked the gateway for, per query shape.
    ///
    /// This is the number that decides whether a response was truncated: the
    /// gateway clamps the caller's cap against the grant's own `row_limit`
    /// and the gateway-wide ceiling, so a shape whose cap is below both is
    /// never truncated and the two paths stay comparable.
    pub row_limit_per_shape: Vec<ShapeRowLimit>,
    /// The statement timeout the harness's own client enforced on the wire,
    /// in milliseconds.
    ///
    /// The database-side `statement_timeout` is the gateway's grant policy
    /// and is not observable from outside; this is the harness's ceiling.
    pub statement_timeout_ms: u64,
    /// The number of rows (or documents) seeded into the target before the
    /// run. The query shapes are written against this size, so a reader
    /// cannot interpret the latency without it.
    pub seed_rows: i64,
}

/// The row cap the harness requested for one query shape.
#[derive(Debug, Clone, Serialize)]
pub struct ShapeRowLimit {
    pub shape: &'static str,
    pub limit: u32,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub environment: Environment,
    /// The backend this run measured.
    pub backend: &'static str,
    /// The configuration this run actually applied. Travels with the numbers
    /// so they can be interpreted without the command line.
    pub effective_config: EffectiveConfig,
    pub measurements: Vec<Measurement>,
    /// The horizontal-scaling rows, if that phase ran. Empty when it did not.
    pub scaling: Vec<ScalingRow>,
    /// The MySQL rejection verdict. `None` when the check was not requested.
    pub mysql_rejection: Option<MySqlRejection>,
    /// What this run deliberately does not measure. Serialized so the caveat
    /// travels with the data instead of living only in prose someone may not
    /// copy across.
    pub not_measured: Vec<&'static str>,
}

impl Report {
    pub fn new(
        environment: Environment,
        effective_config: EffectiveConfig,
        measurements: Vec<Measurement>,
    ) -> Self {
        let backend = measurements
            .first()
            .map(|m| m.backend)
            .unwrap_or("postgres");
        Report {
            environment,
            backend,
            effective_config,
            measurements,
            scaling: Vec::new(),
            mysql_rejection: None,
            not_measured: not_measured(backend),
        }
    }

    /// Attach the horizontal-scaling rows.
    pub fn with_scaling(mut self, scaling: Vec<ScalingRow>) -> Self {
        self.scaling = scaling;
        self
    }

    /// Attach the MySQL rejection verdict.
    pub fn with_mysql_rejection(mut self, verdict: MySqlRejection) -> Self {
        self.mysql_rejection = Some(verdict);
        self
    }

    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn markdown(&self) -> String {
        let mut out = String::new();
        let env = &self.environment;

        out.push_str("### Environment\n\n");
        out.push_str("| | |\n|---|---|\n");
        out.push_str(&format!(
            "| CPU | {} × {} |\n",
            env.cpu_count, env.cpu_model
        ));
        out.push_str(&format!("| Virtualization | {} |\n", env.virtualization));
        if let Some(steal) = env.cpu_steal_pct_since_boot {
            out.push_str(&format!("| CPU steal since boot | {steal:.4}% |\n"));
        }
        if let Some(mem) = env.mem_total_gib {
            out.push_str(&format!("| Memory | {mem:.1} GiB |\n"));
        }
        out.push_str(&format!("| OS / kernel | {} / {} |\n", env.os, env.kernel));
        out.push_str(&format!("| Toolchain | {} |\n", env.rustc));
        out.push_str(&format!(
            "| Gateway | v{} @ `{}`{} |\n",
            env.gateway_version,
            env.git_commit.chars().take(12).collect::<String>(),
            if env.git_dirty { " (dirty)" } else { "" }
        ));
        out.push_str(&format!("| Backend measured | {} |\n", self.backend));
        out.push_str(
            "\nLoad generator, gateway and database all run on this one host — \
             see the caveat below.\n\n",
        );

        out.push_str("### Effective configuration\n\n");
        out.push_str(
            "The configuration this run actually applied, so the numbers above \
             can be interpreted without the command line. The row cap is the \
             one the harness requested per shape; the gateway clamps it \
             against the grant's own `row_limit` and its ceiling, so a shape \
             capped below both is never truncated.\n\n",
        );
        let cfg = &self.effective_config;
        out.push_str("| | |\n|---|---|\n");
        out.push_str(&format!("| Backend | {} |\n", cfg.backend));
        out.push_str(&format!("| Server | `{}` |\n", cfg.server));
        out.push_str(&format!("| Database | `{}` |\n", cfg.database));
        out.push_str(&format!(
            "| Direct baseline database | `{}` |\n",
            cfg.direct_database
        ));
        out.push_str(&format!(
            "| Direct baseline target | `{}` |\n",
            cfg.direct_target_host
        ));
        out.push_str(&format!("| Concurrency | {} |\n", cfg.concurrency));
        out.push_str(&format!(
            "| Requests per phase | {} |\n",
            cfg.requests_per_phase
        ));
        out.push_str(&format!("| Warmup requests | {} |\n", cfg.warmup));
        out.push_str(&format!(
            "| Statement timeout (harness client) | {} ms |\n",
            cfg.statement_timeout_ms
        ));
        out.push_str(&format!("| Seed rows | {} |\n", cfg.seed_rows));
        for entry in &cfg.row_limit_per_shape {
            out.push_str(&format!(
                "| Row cap — `{}` | {} |\n",
                entry.shape, entry.limit
            ));
        }
        out.push('\n');

        out.push_str("### Latency\n\n");
        out.push_str(&format!(
            "Every row: same {} query, same host, same moment, run directly \
             against the database and through the gateway.\n\n",
            self.backend
        ));
        out.push_str("| Query | Path | p50 | p95 | p99 | n |\n|---|---|---|---|---|---|\n");
        for m in &self.measurements {
            out.push_str(&format!(
                "| {} | direct | {:.2}ms | {:.2}ms | {:.2}ms | {} |\n",
                m.description, m.direct.p50_ms, m.direct.p95_ms, m.direct.p99_ms, m.direct.n
            ));
            out.push_str(&format!(
                "| | **gateway** | **{:.2}ms** | **{:.2}ms** | **{:.2}ms** | {} |\n",
                m.gateway.p50_ms, m.gateway.p95_ms, m.gateway.p99_ms, m.gateway.n
            ));
        }

        out.push_str("\n### Added by the gateway\n\n");
        out.push_str(
            "Differences *between the two distributions at each percentile* — not \
             the percentile of per-request differences, which two independent runs \
             cannot give you.\n\n",
        );
        out.push_str("| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |\n");
        out.push_str("|---|---|---|---|---|---|---|\n");
        for m in &self.measurements {
            // `{:+.2}` puts the sign inside the formatter so a percentile where
            // the gateway edges out the baseline prints `-0.42ms`, not `+-0.42ms`.
            out.push_str(&format!(
                "| {} | {:+.2}ms | {:+.2}ms | {:+.2}ms | {:.2}× | {:.1}% | {} |\n",
                m.description,
                m.overhead.p50_delta_ms,
                m.overhead.p95_delta_ms,
                m.overhead.p99_delta_ms,
                m.overhead.p50_ratio,
                m.baseline_drift_pct,
                if m.trustworthy() { "yes" } else { "**no**" }
            ));
        }

        let shaky: Vec<_> = self
            .measurements
            .iter()
            .filter(|m| !m.trustworthy())
            .collect();
        if !shaky.is_empty() {
            out.push_str(&format!(
                "\n> Rows marked **no** had baseline drift above {MAX_TRUSTED_DRIFT_PCT}% or \
                 non-zero errors. The host moved during the run; treat those deltas as \
                 indicative only.\n",
            ));
        }

        out.push_str("\n### Throughput and resource use\n\n");
        out.push_str(
            "Throughput is **completed requests per second on this host**, not an \
             absolute capacity number: the load generator, the gateway and the \
             database compete for the same cores, so this is what the whole box \
             managed. Resource figures are the gateway process's own, sampled \
             from `/proc` during the measured phase.\n\n",
        );
        out.push_str(
            "| Query | Path | req/s | peak RSS | CPU s | samples |\n|---|---|---|---|---|---|\n",
        );
        for m in &self.measurements {
            out.push_str(&format!(
                "| {} | direct | {:.0} | — | — | — |\n",
                m.description, m.direct_throughput.requests_per_sec
            ));
            out.push_str(&format!(
                "| | **gateway** | **{:.0}** | {:.1} MiB | {:.2} | {} |\n",
                m.gateway_throughput.requests_per_sec,
                m.gateway_resources.peak_rss_bytes as f64 / (1024.0 * 1024.0),
                m.gateway_resources.cpu_seconds,
                m.gateway_resources.samples
            ));
        }

        if !self.scaling.is_empty() {
            out.push_str("\n### Horizontal scaling\n\n");
            out.push_str(&format!(
                "> **{}** — these rows do not publish a scaling law.\n\n",
                ScalingRow::caveat()
            ));
            out.push_str(
                "| Instances | URLs used | req/s | p50 | p95 | p99 | errors |\n\
                 |---|---|---|---|---|---|---|\n",
            );
            for row in &self.scaling {
                out.push_str(&format!(
                    "| {} | {} | {:.0} | {:.2}ms | {:.2}ms | {:.2}ms | {} |\n",
                    row.instances,
                    row.urls_used,
                    row.throughput.requests_per_sec,
                    row.p50_ms,
                    row.p95_ms,
                    row.p99_ms,
                    row.errors
                ));
            }
        }

        if let Some(verdict) = &self.mysql_rejection {
            out.push_str("\n### MySQL query-target rejection\n\n");
            out.push_str(
                "MySQL is **not** a query target in this gateway. This section \
                 records the verification of that fact — it is not a latency \
                 measurement and is deliberately kept out of the tables above.\n\n",
            );
            out.push_str("| Check | Result |\n|---|---|\n");
            out.push_str(&format!(
                "| Boot-time rejection of `kind: {}` | {} |\n",
                verdict.kind,
                if verdict.boot_rejected {
                    "**rejected**"
                } else {
                    "**NOT rejected**"
                }
            ));
            out.push_str(&format!(
                "| Runtime backstop maps to the stable `internal` code | {} |\n",
                if verdict.runtime_backstop_ok {
                    "**ok**"
                } else {
                    "**not ok**"
                }
            ));
            if let Some(message) = &verdict.rejection_message {
                out.push_str(&format!("| Rejection message | `{message}` |\n"));
            }
            if let Some(reason) = &verdict.not_run_reason {
                out.push_str(&format!("| Not run | {reason} |\n"));
            }
        }

        out.push_str("\n### Not measured\n\n");
        for item in &self.not_measured {
            out.push_str(&format!("- {item}\n"));
        }
        out
    }
}

/// What this harness deliberately does not measure, and why.
///
/// Each entry names the reason it cannot be answered on one host. MongoDB is
/// **not** on this list any more — the harness measures the mongo adapter
/// against a real MongoDB with the same discipline as the postgres path.
fn not_measured(backend: &str) -> Vec<&'static str> {
    let mut items = vec![
        "absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and \
         the database, so the throughput reported above is what the whole box managed, not what \
         the gateway alone can serve",
        "horizontal scaling as a scaling law — adding gateway instances to a host that is already \
         saturated measures contention, not scaling; the scaling section above is labelled as such \
         and needs a separate load host to become a scaling result",
        "multi-host or multi-region behaviour — one host, one set of cores, one database",
        "TLS termination cost — the bench gateway runs with TLS disabled",
    ];
    if backend != "postgres-write" {
        items.push(
            "write-path overhead in this run — its grants are `query_read` (and the mongo adapter \
             is read-only by construction); `--backend postgres-write` measures the write tier",
        );
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::PhaseResult;

    fn phase(p50: f64, errors: u64) -> PhaseResult {
        PhaseResult {
            summary: Summary::from_samples(vec![p50; 100]).expect("non-empty"),
            errors,
            first_error: None,
            duration_ms: 1_000.0,
            completed: 100,
            samples_ms: vec![p50; 100],
        }
    }

    fn plan() -> Plan {
        Plan {
            concurrency: 4,
            requests: 100,
            warmup: 0,
        }
    }

    fn measurement() -> Measurement {
        Measurement::new(
            Shape::PointLookup,
            plan(),
            phase(1.0, 0),
            phase(2.0, 0),
            phase(1.0, 0),
            0.0,
            ResourceUsage {
                peak_rss_bytes: 64 * 1024 * 1024,
                cpu_seconds: 1.25,
                samples: 12,
            },
        )
    }

    fn config() -> EffectiveConfig {
        EffectiveConfig {
            backend: "postgres",
            server: "target".to_string(),
            database: "app".to_string(),
            direct_database: "app".to_string(),
            direct_target_host: "localhost:5434".to_string(),
            concurrency: 4,
            requests_per_phase: 100,
            warmup: 10,
            row_limit_per_shape: vec![ShapeRowLimit {
                shape: "point_lookup",
                limit: 10,
            }],
            statement_timeout_ms: 30_000,
            seed_rows: 50_000,
        }
    }

    #[test]
    fn a_clean_run_is_trustworthy() {
        let m = measurement();
        assert!(m.trustworthy());
        assert!((m.overhead.p50_delta_ms - 1.0).abs() < 1e-9);
        assert!((m.overhead.p50_ratio - 2.0).abs() < 1e-9);
    }

    #[test]
    fn errors_disqualify_a_row_even_with_zero_drift() {
        let m = Measurement::new(
            Shape::Aggregate,
            plan(),
            phase(1.0, 0),
            phase(2.0, 3),
            phase(1.0, 0),
            0.0,
            ResourceUsage::unavailable(),
        );
        assert!(
            !m.trustworthy(),
            "a row with failed requests must be flagged"
        );
    }

    #[test]
    fn drift_above_five_percent_disqualifies_a_row() {
        let m = Measurement::new(
            Shape::RangeScan,
            plan(),
            phase(1.0, 0),
            phase(2.0, 0),
            phase(1.2, 0),
            20.0,
            ResourceUsage::unavailable(),
        );
        assert!(!m.trustworthy());
        // The warning must reach the published table, not just the struct.
        let md = Report::new(Environment::capture(), config(), vec![m]).markdown();
        assert!(
            md.contains("**no**"),
            "shaky row must be flagged in markdown"
        );
        assert!(md.contains("indicative only"), "and explained");
    }

    #[test]
    fn negative_overhead_renders_without_a_double_sign() {
        // p99 gateway faster than direct → overhead is negative. The formatter
        // must own the sign so the table never emits `+-0.42ms`.
        let m = Measurement::new(
            Shape::PointLookup,
            plan(),
            phase(2.0, 0),
            phase(1.5, 0),
            phase(2.0, 0),
            0.0,
            ResourceUsage::unavailable(),
        );
        let md = Report::new(Environment::capture(), config(), vec![m]).markdown();
        assert!(
            !md.contains("+-"),
            "sign flag must own the sign, saw a stacked sign in:\n{md}"
        );
        assert!(
            md.contains("-0.50ms"),
            "expected the negative delta to appear as `-0.50ms`:\n{md}"
        );
    }

    #[test]
    fn markdown_always_states_what_was_not_measured() {
        let report = Report::new(Environment::capture(), config(), vec![measurement()]);
        let md = report.markdown();
        assert!(md.contains("Not measured"));
        assert!(md.contains("horizontal scaling"));
        assert!(md.contains("CPU steal") || report.environment.cpu_steal_pct_since_boot.is_none());
    }

    /// The write-path item is listed exactly when the run did not measure writes.
    #[test]
    fn write_path_is_unmeasured_only_outside_the_write_backend() {
        let write_items = |backend: &str| {
            not_measured(backend)
                .into_iter()
                .filter(|item| item.starts_with("write-path overhead"))
                .count()
        };
        assert_eq!(write_items("postgres"), 1);
        assert_eq!(write_items("mongo"), 1);
        assert_eq!(write_items("postgres-write"), 0);
    }

    /// MongoDB is measured now — it must not be listed as unmeasured.
    #[test]
    fn mongodb_is_not_listed_as_unmeasured() {
        let md = Report::new(Environment::capture(), config(), vec![measurement()]).markdown();
        assert!(
            !md.to_lowercase().contains("mongodb overhead"),
            "mongo is measured; the not-measured list must not exclude it:\n{md}"
        );
    }

    /// The throughput and resource figures must reach the Markdown — a
    /// number that only exists in the JSON is not published.
    #[test]
    fn throughput_and_resource_figures_reach_the_markdown() {
        let md = Report::new(Environment::capture(), config(), vec![measurement()]).markdown();
        assert!(md.contains("Throughput and resource use"), "{md}");
        assert!(md.contains("req/s"), "{md}");
        assert!(md.contains("peak RSS"), "{md}");
        // 100 completed requests over 1 s.
        assert!(md.contains("100"), "{md}");
    }

    /// The scaling section must carry the contention label, not present the
    /// numbers as a scaling law.
    #[test]
    fn the_scaling_section_is_labelled_as_contention() {
        let row = ScalingRow {
            instances: 2,
            urls_used: 2,
            throughput: Throughput::new(100, 1_000.0),
            p50_ms: 1.0,
            p95_ms: 2.0,
            p99_ms: 3.0,
            errors: 0,
            samples_ms: vec![1.0; 100],
        };
        let md = Report::new(Environment::capture(), config(), vec![measurement()])
            .with_scaling(vec![row])
            .markdown();
        assert!(md.contains("Horizontal scaling"), "{md}");
        assert!(
            md.contains("contention on a single shared host"),
            "the scaling rows must carry the contention label:\n{md}"
        );
        assert!(md.contains("do not publish a scaling law"), "{md}");
    }

    /// The MySQL verdict must be in its own section, distinct from the
    /// latency tables.
    #[test]
    fn the_mysql_verdict_has_its_own_section() {
        let verdict = crate::mysql_reject::verify(None);
        let md = Report::new(Environment::capture(), config(), vec![measurement()])
            .with_mysql_rejection(verdict)
            .markdown();
        assert!(md.contains("MySQL query-target rejection"), "{md}");
        assert!(md.contains("not a latency measurement"), "{md}");
        // The latency table must not have picked up a MySQL row.
        assert!(!md.contains("| MySQL | direct |"), "{md}");
    }

    /// The published percentiles must be re-derivable from the raw samples
    /// in the result file. This is the whole reason the samples are kept: a
    /// reader who does not trust the harness's own arithmetic can check it.
    #[test]
    fn the_published_percentiles_are_re_derivable_from_the_raw_samples() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let summary = Summary::from_samples(samples.clone()).expect("non-empty");
        let phase = || PhaseResult {
            summary: summary.clone(),
            errors: 0,
            first_error: None,
            duration_ms: 1_000.0,
            completed: 100,
            samples_ms: samples.clone(),
        };
        let m = Measurement::new(
            Shape::PointLookup,
            plan(),
            phase(),
            phase(),
            phase(),
            0.0,
            ResourceUsage::unavailable(),
        );

        // Re-derive the percentiles from the published samples alone.
        let mut sorted = m.gateway_samples_ms.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let nearest_rank = |pct: f64| {
            let rank = (pct / 100.0 * sorted.len() as f64).ceil() as usize;
            sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
        };
        assert_eq!(nearest_rank(50.0), m.gateway.p50_ms);
        assert_eq!(nearest_rank(95.0), m.gateway.p95_ms);
        assert_eq!(nearest_rank(99.0), m.gateway.p99_ms);
        assert_eq!(m.gateway_samples_ms.len(), m.gateway.n);
    }

    /// The recheck's raw samples must be published beside its percentiles:
    /// discarding them would leave the baseline drift — and the recheck's own
    /// percentiles — un-re-derivable from the result file.
    #[test]
    fn the_rechecks_raw_samples_are_published_beside_its_percentiles() {
        let recheck_samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let recheck = PhaseResult {
            summary: Summary::from_samples(recheck_samples.clone()).expect("non-empty"),
            errors: 0,
            first_error: None,
            duration_ms: 1_000.0,
            completed: 100,
            samples_ms: recheck_samples.clone(),
        };
        let m = Measurement::new(
            Shape::PointLookup,
            plan(),
            phase(1.0, 0),
            phase(2.0, 0),
            recheck,
            0.0,
            ResourceUsage::unavailable(),
        );
        assert_eq!(m.direct_recheck_samples_ms, recheck_samples);
        assert_eq!(m.direct_recheck_samples_ms.len(), m.direct_recheck.n);

        // And they must reach the JSON, not only the struct.
        let json = serde_json::to_value(Report::new(Environment::capture(), config(), vec![m]))
            .expect("report serializes");
        assert_eq!(
            json["measurements"][0]["direct_recheck_samples_ms"]
                .as_array()
                .map(|a| a.len()),
            Some(100),
            "{json}"
        );
    }

    /// The effective configuration must travel in the result file and reach
    /// the published table. A reader who only has the JSON has to be able to
    /// tell which database, which workload and which row cap produced the
    /// numbers — the README promises the file carries it.
    #[test]
    fn the_effective_configuration_is_published() {
        let report = Report::new(Environment::capture(), config(), vec![measurement()]);

        let json = serde_json::to_value(&report).expect("report serializes");
        let cfg = &json["effective_config"];
        assert_eq!(cfg["server"], "target", "{json}");
        assert_eq!(cfg["database"], "app", "{json}");
        assert_eq!(cfg["backend"], "postgres", "{json}");
        assert_eq!(cfg["concurrency"], 4, "{json}");
        assert_eq!(cfg["requests_per_phase"], 100, "{json}");
        assert_eq!(cfg["warmup"], 10, "{json}");
        assert_eq!(cfg["statement_timeout_ms"], 30_000, "{json}");
        assert_eq!(cfg["seed_rows"], 50_000, "{json}");
        assert_eq!(cfg["direct_target_host"], "localhost:5434", "{json}");
        assert_eq!(
            cfg["row_limit_per_shape"][0]["shape"], "point_lookup",
            "{json}"
        );
        assert_eq!(cfg["row_limit_per_shape"][0]["limit"], 10, "{json}");

        let md = report.markdown();
        assert!(md.contains("Effective configuration"), "{md}");
        assert!(md.contains("`target`"), "{md}");
        assert!(md.contains("Seed rows"), "{md}");
        assert!(md.contains("50000"), "{md}");
    }
}
