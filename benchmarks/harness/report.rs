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
use crate::stats::{Overhead, Summary};
use crate::workload::Shape;

#[derive(Debug, Serialize)]
pub struct Measurement {
    pub shape: Shape,
    pub description: &'static str,
    pub concurrency: u32,
    pub requests_per_phase: u64,
    pub direct: Summary,
    pub gateway: Summary,
    /// Second baseline run, after the gateway phase.
    pub direct_recheck: Summary,
    /// Difference between the two baseline runs, as a percentage of the first.
    pub baseline_drift_pct: f64,
    pub overhead: Overhead,
    pub direct_errors: u64,
    pub gateway_errors: u64,
    pub first_gateway_error: Option<String>,
}

impl Measurement {
    pub fn new(
        shape: Shape,
        plan: Plan,
        base_first: PhaseResult,
        measured: PhaseResult,
        base_second: PhaseResult,
        drift_pct: f64,
    ) -> Self {
        let overhead = Overhead::between(&base_first.summary, &measured.summary);
        Measurement {
            shape,
            description: shape.description(),
            concurrency: plan.concurrency,
            requests_per_phase: plan.requests,
            direct: base_first.summary,
            gateway: measured.summary,
            direct_recheck: base_second.summary,
            baseline_drift_pct: drift_pct,
            overhead,
            direct_errors: base_first.errors,
            gateway_errors: measured.errors,
            first_gateway_error: measured.first_error,
        }
    }

    /// Whether this row is solid enough to publish without a caveat.
    fn trustworthy(&self) -> bool {
        self.baseline_drift_pct <= 5.0 && self.gateway_errors == 0 && self.direct_errors == 0
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub environment: Environment,
    pub measurements: Vec<Measurement>,
    /// What this run deliberately does not measure. Serialized so the caveat
    /// travels with the data instead of living only in prose someone may not
    /// copy across.
    pub not_measured: Vec<&'static str>,
}

impl Report {
    pub fn new(environment: Environment, measurements: Vec<Measurement>) -> Self {
        Report {
            environment,
            measurements,
            not_measured: vec![
                "absolute throughput ceiling (qps) — load generator shares CPU with gateway and database",
                "horizontal scaling across gateway instances — same reason; needs a separate load host",
                "MongoDB overhead — harness covers the Postgres adapter only",
            ],
        }
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
        out.push_str(
            "\nLoad generator, gateway and database all run on this one host — \
             see the caveat below.\n\n",
        );

        out.push_str("### Latency\n\n");
        out.push_str(
            "Every row: same SQL, same host, same moment, run directly against \
             Postgres and through the gateway.\n\n",
        );
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
            out.push_str(&format!(
                "| {} | +{:.2}ms | +{:.2}ms | +{:.2}ms | {:.2}× | {:.1}% | {} |\n",
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
            out.push_str(
                "\n> Rows marked **no** had baseline drift above 5% or non-zero errors. \
                          The host moved during the run; treat those deltas as indicative only.\n",
            );
        }

        out.push_str("\n### Not measured\n\n");
        for item in &self.not_measured {
            out.push_str(&format!("- {item}\n"));
        }
        out
    }
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
        }
    }

    fn plan() -> Plan {
        Plan {
            concurrency: 4,
            requests: 100,
            warmup: 0,
        }
    }

    #[test]
    fn a_clean_run_is_trustworthy() {
        let m = Measurement::new(
            Shape::PointLookup,
            plan(),
            phase(1.0, 0),
            phase(2.0, 0),
            phase(1.0, 0),
            0.0,
        );
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
        );
        assert!(!m.trustworthy());
        // The warning must reach the published table, not just the struct.
        let md = Report::new(Environment::capture(), vec![m]).markdown();
        assert!(
            md.contains("**no**"),
            "shaky row must be flagged in markdown"
        );
        assert!(md.contains("indicative only"), "and explained");
    }

    #[test]
    fn markdown_always_states_what_was_not_measured() {
        let report = Report::new(
            Environment::capture(),
            vec![Measurement::new(
                Shape::PointLookup,
                plan(),
                phase(1.0, 0),
                phase(2.0, 0),
                phase(1.0, 0),
                0.0,
            )],
        );
        let md = report.markdown();
        assert!(md.contains("Not measured"));
        assert!(md.contains("horizontal scaling"));
        assert!(md.contains("CPU steal") || report.environment.cpu_steal_pct_since_boot.is_none());
    }
}
