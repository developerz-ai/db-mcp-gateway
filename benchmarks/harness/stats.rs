//! Latency summaries.
//!
//! Percentiles are computed by exact rank over the sorted sample, not by
//! interpolation or a sketch. The samples here number in the thousands, so
//! there is no reason to approximate — and an approximation would be one more
//! thing a reader has to trust.

use serde::Serialize;

/// A latency distribution in milliseconds.
///
/// Deliberately carries `n` alongside the percentiles. A p99 over 200 samples
/// is two data points wearing a suit; publishing the count lets a reader judge
/// that for themselves.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub n: usize,
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    /// Coefficient of variation (stddev / mean), as a percentage. The
    /// measurement-quality signal: a high CV means the box moved under us and
    /// the percentiles below describe the neighbours as much as the code.
    pub cv_pct: f64,
}

impl Summary {
    /// `samples` is consumed and sorted in place — the caller has no use for
    /// the original order, and sorting a copy would double the peak footprint
    /// on the larger runs.
    pub fn from_samples(mut samples: Vec<f64>) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        // Latencies are always finite and non-NaN (they come from `Instant`
        // deltas), so a total order is safe here.
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = samples.len();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let variance = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n as f64;
        let stddev = variance.sqrt();

        Some(Summary {
            n,
            min_ms: samples[0],
            p50_ms: percentile(&samples, 50.0),
            p90_ms: percentile(&samples, 90.0),
            p95_ms: percentile(&samples, 95.0),
            p99_ms: percentile(&samples, 99.0),
            max_ms: samples[n - 1],
            mean_ms: mean,
            cv_pct: if mean > 0.0 {
                100.0 * stddev / mean
            } else {
                0.0
            },
        })
    }
}

/// Nearest-rank percentile: the smallest value at or below which at least
/// `pct` percent of the sample falls. `sorted` must be ascending and non-empty.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    let rank = (pct / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Completed requests per second over a phase.
///
/// **Not** an absolute capacity number. The load generator, the gateway and
/// the database all share one host, so this figure is what the *whole box*
/// managed — it bounds the gateway from above rather than describing the
/// gateway. Every place it is published says so; see
/// [`crate::report::Report::markdown`].
///
/// Derived from the phase wall clock and the count of requests that
/// *completed*, so failed requests do not inflate it.
#[derive(Debug, Clone, Serialize)]
pub struct Throughput {
    /// Requests that completed successfully.
    pub completed: u64,
    /// Wall-clock duration of the measured phase, in milliseconds.
    pub duration_ms: f64,
    /// `completed / (duration_ms / 1000)`.
    pub requests_per_sec: f64,
}

impl Throughput {
    pub fn new(completed: u64, duration_ms: f64) -> Self {
        let requests_per_sec = if duration_ms > 0.0 {
            completed as f64 / (duration_ms / 1000.0)
        } else {
            f64::NAN
        };
        Throughput {
            completed,
            duration_ms,
            requests_per_sec,
        }
    }
}

/// What the gateway process consumed while a phase ran.
///
/// Read from `/proc` for the gateway's PID: peak resident set size, CPU
/// seconds burned (user + system), and how many samples were taken. The
/// sample count matters as much as the numbers — a phase that lasted 40 ms
/// and caught one sample says almost nothing, and a reader needs to be able
/// to see that.
///
/// `peak_rss_bytes` is a high-water mark across the samples, not the value
/// at the end of the phase: RSS rarely falls, so the last sample would
/// understate a phase that allocated and freed.
///
/// `cpu_seconds` is a **difference**, not a cumulative counter: it is the
/// process's CPU at the phase's last sample minus its CPU at the phase's
/// first sample. `/proc` reports CPU since the process started, so a
/// cumulative figure would charge the phase for boot, for both baseline
/// phases and for every earlier shape's gateway phase.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceUsage {
    pub peak_rss_bytes: u64,
    /// CPU seconds (user + system) the gateway burned during the phase —
    /// the delta between the phase's first and last `/proc` reading.
    pub cpu_seconds: f64,
    /// Number of `/proc` samples taken. A reader can see how much of the
    /// phase was actually observed. A single sample is the baseline alone,
    /// so it necessarily yields a CPU delta of zero.
    pub samples: u64,
}

impl ResourceUsage {
    /// No observation possible — the process is gone or `/proc` is not
    /// readable. `samples: 0` says so unambiguously; the zero
    /// `cpu_seconds` alongside it means "not observed", not "no CPU".
    pub fn unavailable() -> Self {
        ResourceUsage {
            peak_rss_bytes: 0,
            cpu_seconds: 0.0,
            samples: 0,
        }
    }
}

/// One row of the horizontal-scaling phase: the same workload driven against
/// `instances` gateway instances on one host.
///
/// **This is contention on a single shared host, not a scaling law.** The
/// load generator, the N gateways and the database all share the same cores,
/// so adding instances adds processes fighting for the same CPU. The row
/// records what the box did; it does not extrapolate to a fleet. The label
/// travels with the data — [`Self::caveat`] is emitted verbatim into the
/// report.
#[derive(Debug, Clone, Serialize)]
pub struct ScalingRow {
    /// How many gateway instances were behind the URL list.
    pub instances: usize,
    /// How many URLs were actually used (a list shorter than `instances`
    /// means the operator passed fewer gateways than instances asked for).
    pub urls_used: usize,
    pub throughput: Throughput,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    /// Requests that failed during this row's phase.
    pub errors: u64,
    /// The raw per-request latencies, in measurement order — so the
    /// percentiles above can be re-derived from the result file.
    pub samples_ms: Vec<f64>,
}

/// The caveat that must accompany every scaling row. One constant so the
/// JSON and the Markdown cannot drift apart.
pub const SCALING_CAVEAT: &str = "contention on a single shared host — the load generator, the \
                                  gateway instances and the database share the same cores, so this \
                                  is not a scaling law";

impl ScalingRow {
    /// The label rendered next to the row.
    pub fn caveat() -> &'static str {
        SCALING_CAVEAT
    }
}

/// How much slower one distribution is than another, percentile by percentile.
///
/// Every field is a difference *between the two distributions at that
/// percentile* — it is emphatically **not** the percentile of per-request
/// differences. Those are different statistics and only the first one is
/// computable from two independent runs. Naming it `_delta` and saying so here
/// is the whole reason this type exists instead of subtracting inline.
#[derive(Debug, Clone, Serialize)]
pub struct Overhead {
    pub p50_delta_ms: f64,
    pub p95_delta_ms: f64,
    pub p99_delta_ms: f64,
    pub mean_delta_ms: f64,
    /// `gateway.p50 / direct.p50`. Often the more honest headline than the
    /// absolute delta: "1.4x" survives a change of hardware, "+2ms" does not.
    pub p50_ratio: f64,
}

impl Overhead {
    pub fn between(direct: &Summary, gateway: &Summary) -> Self {
        Overhead {
            p50_delta_ms: gateway.p50_ms - direct.p50_ms,
            p95_delta_ms: gateway.p95_ms - direct.p95_ms,
            p99_delta_ms: gateway.p99_ms - direct.p99_ms,
            mean_delta_ms: gateway.mean_ms - direct.mean_ms,
            p50_ratio: if direct.p50_ms > 0.0 {
                gateway.p50_ms / direct.p50_ms
            } else {
                f64::NAN
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_use_exact_nearest_rank() {
        let s: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let summary = Summary::from_samples(s).expect("non-empty");
        assert_eq!(summary.p50_ms, 50.0);
        assert_eq!(summary.p95_ms, 95.0);
        assert_eq!(summary.p99_ms, 99.0);
        assert_eq!(summary.min_ms, 1.0);
        assert_eq!(summary.max_ms, 100.0);
    }

    #[test]
    fn single_sample_reports_itself_at_every_percentile() {
        let summary = Summary::from_samples(vec![7.0]).expect("non-empty");
        assert_eq!(summary.p50_ms, 7.0);
        assert_eq!(summary.p99_ms, 7.0);
        assert_eq!(summary.cv_pct, 0.0);
    }

    #[test]
    fn empty_sample_has_no_summary() {
        assert!(Summary::from_samples(vec![]).is_none());
    }

    #[test]
    fn constant_distribution_has_zero_spread() {
        let summary = Summary::from_samples(vec![5.0; 50]).expect("non-empty");
        assert_eq!(summary.cv_pct, 0.0);
        assert_eq!(summary.min_ms, summary.max_ms);
    }

    /// Throughput must come from *completed* requests over the phase's wall
    /// clock — 200 requests in 2 s is 100 rps, not 200/2000ms.
    #[test]
    fn throughput_is_completed_requests_over_wall_clock() {
        let t = Throughput::new(200, 2_000.0);
        assert_eq!(t.requests_per_sec, 100.0);
        assert_eq!(t.completed, 200);
        assert_eq!(t.duration_ms, 2_000.0);
    }

    #[test]
    fn throughput_of_a_zero_length_phase_is_not_a_number() {
        // A zero-duration phase means the clock never ran; reporting 0 rps
        // would be a lie and infinity would be noise. NaN says "no answer".
        let t = Throughput::new(10, 0.0);
        assert!(t.requests_per_sec.is_nan());
    }

    #[test]
    fn unavailable_resource_usage_carries_no_samples() {
        let usage = ResourceUsage::unavailable();
        assert_eq!(usage.samples, 0);
        assert_eq!(usage.peak_rss_bytes, 0);
        assert_eq!(usage.cpu_seconds, 0.0);
    }

    /// The scaling caveat must name the host-sharing reason — a reader who
    /// sees only "1.4x at 4 instances" must not be able to mistake it for a
    /// scaling law.
    #[test]
    fn scaling_caveat_names_the_shared_host() {
        assert!(ScalingRow::caveat().contains("single shared host"));
    }
}
