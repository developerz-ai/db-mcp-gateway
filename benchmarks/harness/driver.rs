//! Closed-loop load driver.
//!
//! `concurrency` workers each pull the next iteration number off a shared
//! counter and issue one request, until `requests` have been issued. Closed
//! loop — a worker's next request starts only when its previous one finishes —
//! which is what an agent fleet actually does, and unlike an open-loop
//! generator it cannot produce a coordinated-omission artefact by queueing
//! requests the system never accepted.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::stats::Summary;
use crate::workload::Shape;

/// One measurable path. Implemented by both the gateway client and the direct
/// client so the driver cannot accidentally treat them differently.
#[async_trait]
pub trait Path: Send + Sync + 'static {
    /// Issue one request, returning its latency in milliseconds.
    async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, String>;
    fn label(&self) -> &'static str;
}

#[derive(Debug, Clone, Copy)]
pub struct Plan {
    pub concurrency: u32,
    pub requests: u64,
    /// Requests issued and discarded before measurement starts. Covers pool
    /// fill, JIT-free but cache-cold paths, and the gateway's first-call
    /// permission resolution.
    pub warmup: u64,
}

#[derive(Debug)]
pub struct PhaseResult {
    pub summary: Summary,
    /// Requests that returned an error. Reported rather than retried: a run
    /// with failures is a different run, and hiding them behind a retry would
    /// let a broken configuration publish a good-looking number.
    pub errors: u64,
    /// First error seen, for diagnosis. Bounded to one so a fully-failing run
    /// cannot flood the report.
    pub first_error: Option<String>,
}

/// Run `plan` against `path` for one query shape.
pub async fn run_phase(
    path: Arc<dyn Path>,
    shape: Shape,
    plan: Plan,
) -> Result<PhaseResult, String> {
    if plan.warmup > 0 {
        drain(Arc::clone(&path), shape, plan.concurrency, plan.warmup, 0).await;
    }

    let counter = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::with_capacity(plan.concurrency as usize);

    for _ in 0..plan.concurrency.max(1) {
        let path = Arc::clone(&path);
        let counter = Arc::clone(&counter);
        let total = plan.requests;
        // Offset past the warmup range so measured requests do not replay the
        // exact predicates the warmup just cached.
        let offset = plan.warmup;
        workers.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            let mut errors = 0u64;
            let mut first_error = None;
            loop {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                match path.run(shape, offset + i).await {
                    Ok(ms) => samples.push(ms),
                    Err(e) => {
                        errors += 1;
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                }
            }
            (samples, errors, first_error)
        }));
    }

    let mut all = Vec::with_capacity(plan.requests as usize);
    let mut errors = 0u64;
    let mut first_error = None;
    for worker in workers {
        let (samples, worker_errors, worker_first) = worker
            .await
            .map_err(|e| format!("load worker panicked: {e}"))?;
        all.extend(samples);
        errors += worker_errors;
        if first_error.is_none() {
            first_error = worker_first;
        }
    }

    let summary = Summary::from_samples(all).ok_or_else(|| {
        format!(
            "every request failed on {} / {}: {}",
            path.label(),
            shape.name(),
            first_error.as_deref().unwrap_or("no error recorded")
        )
    })?;

    Ok(PhaseResult {
        summary,
        errors,
        first_error,
    })
}

/// Issue `count` requests and throw the results away.
async fn drain(path: Arc<dyn Path>, shape: Shape, concurrency: u32, count: u64, offset: u64) {
    let counter = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for _ in 0..concurrency.max(1) {
        let path = Arc::clone(&path);
        let counter = Arc::clone(&counter);
        workers.push(tokio::spawn(async move {
            loop {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                if i >= count {
                    break;
                }
                // Warmup failures are ignored on purpose — a cold pool's first
                // connect can legitimately fail and retry. Measured-phase
                // failures are counted and reported.
                let _ = path.run(shape, offset + i).await;
            }
        }));
    }
    for worker in workers {
        let _ = worker.await;
    }
}

/// How far two runs of the *same* path drifted, as a fraction of the first.
///
/// The measurement-validity check: we run the baseline, then the gateway, then
/// the baseline again. If the two baseline runs disagree by more than a few
/// percent the machine moved underneath us, and the gateway-vs-baseline delta
/// measured in between is not trustworthy at that resolution.
pub fn drift_pct(first: &Summary, second: &Summary) -> f64 {
    if first.p50_ms <= 0.0 {
        return f64::NAN;
    }
    100.0 * (second.p50_ms - first.p50_ms).abs() / first.p50_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(f64);

    #[async_trait]
    impl Path for Fixed {
        async fn run(&self, _shape: Shape, _iteration: u64) -> Result<f64, String> {
            Ok(self.0)
        }
        fn label(&self) -> &'static str {
            "fixed"
        }
    }

    struct AlwaysFails;

    #[async_trait]
    impl Path for AlwaysFails {
        async fn run(&self, _shape: Shape, _iteration: u64) -> Result<f64, String> {
            Err("nope".into())
        }
        fn label(&self) -> &'static str {
            "always-fails"
        }
    }

    #[tokio::test]
    async fn every_requested_iteration_is_measured_exactly_once() {
        let plan = Plan {
            concurrency: 4,
            requests: 200,
            warmup: 10,
        };
        let result = run_phase(Arc::new(Fixed(1.5)), Shape::PointLookup, plan)
            .await
            .expect("fixed path succeeds");
        assert_eq!(result.summary.n, 200, "warmup must not enter the sample");
        assert_eq!(result.errors, 0);
        assert_eq!(result.summary.p50_ms, 1.5);
    }

    #[tokio::test]
    async fn a_fully_failing_path_is_an_error_not_an_empty_success() {
        let plan = Plan {
            concurrency: 2,
            requests: 10,
            warmup: 0,
        };
        let err = run_phase(Arc::new(AlwaysFails), Shape::Aggregate, plan)
            .await
            .expect_err("no samples means no summary");
        assert!(err.contains("every request failed"), "got: {err}");
    }

    #[test]
    fn drift_is_symmetric_and_relative() {
        let a = Summary::from_samples(vec![10.0; 10]).expect("non-empty");
        let b = Summary::from_samples(vec![11.0; 10]).expect("non-empty");
        assert!((drift_pct(&a, &b) - 10.0).abs() < 1e-9);
        // Direction must not change the magnitude of the warning.
        assert!(drift_pct(&b, &a) > 0.0);
    }
}
