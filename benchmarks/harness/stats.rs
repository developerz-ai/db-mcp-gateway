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
}
