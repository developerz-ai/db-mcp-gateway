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
use std::time::{Duration, Instant};

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
    /// Wall-clock duration of the measured phase in milliseconds. Measured
    /// around the workers only — the warmup drain is *not* inside it, because
    /// a cold pool's connect time is not the steady-state cost we are
    /// publishing.
    pub duration_ms: f64,
    /// Requests that completed successfully. Equals `summary.n` — carried
    /// separately so the throughput calculation has an explicit input rather
    /// than re-deriving it from a percentile-bearing struct.
    pub completed: u64,
    /// The raw per-request latencies, in milliseconds, **unsorted** in the
    /// original completion order.
    ///
    /// Kept so the published percentiles can be re-derived from the result
    /// file rather than taken on trust. A `Summary` is a lossy reduction:
    /// from n, p50, p95, p99, min, max and mean you cannot recompute p90 or
    /// the coefficient of variation, let alone check that the numbers came
    /// from one distribution. The raw samples are what make the published
    /// table auditable.
    ///
    /// The samples are the harness's own measurements of its own latency
    /// numbers — no credential, query text or response body is in them.
    pub samples_ms: Vec<f64>,
}

impl PhaseResult {
    /// Throughput for this phase: completed requests over the phase's wall
    /// clock.
    pub fn throughput(&self) -> crate::stats::Throughput {
        crate::stats::Throughput::new(self.completed, self.duration_ms)
    }
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

    // Clock starts once every worker is spawned and immediately before the
    // first request can be issued. `Instant::now()` here, not at spawn time.
    let started = Instant::now();

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

    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;

    let completed = all.len() as u64;
    // `Summary::from_samples` sorts in place, which would destroy the
    // original completion order. The summary is computed from a clone so the
    // raw samples keep the order they were measured in — the order is what
    // makes a reader able to spot a slow patch in the middle of a run.
    let summary = Summary::from_samples(all.clone()).ok_or_else(|| {
        format!(
            "every request failed on {} / {}: {}",
            path.label(),
            shape.name(),
            first_error.as_deref().unwrap_or("no error recorded")
        )
    })?;

    Ok(PhaseResult {
        completed,
        summary,
        errors,
        first_error,
        duration_ms,
        samples_ms: all,
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

/// Samples a running process's CPU and memory from `/proc`.
///
/// The gateway is the process under test, so its own resource usage is what
/// the "resource utilization under load" section reports. Reading `/proc`
/// directly keeps the harness dependency-free and works on any Linux host;
/// on a host without `/proc` every sample simply fails and the phase is
/// reported as unobserved rather than as zero.
///
/// Deliberately *not* a `tokio` task reading the file repeatedly: each
/// sample is a blocking file read of a few hundred bytes, and the harness is
/// a load generator — a few extra syscalls per sample are noise next to the
/// gateway's own work, but a blocking read on the async runtime's worker
/// threads would not be.
pub struct ResourceSampler {
    pid: u32,
    interval: Duration,
    peak_rss_bytes: u64,
    /// The process's cumulative CPU at the first sample — the baseline the
    /// published per-phase figure is measured against.
    ///
    /// `/proc` reports CPU since the process *started*, so publishing that
    /// number as "the CPU burned during this phase" would charge the phase
    /// for boot, for both baseline phases and for every earlier shape's
    /// gateway phase. The first reading is therefore taken as the baseline
    /// and only the difference is published.
    baseline_cpu_seconds: Option<f64>,
    /// CPU seconds burned since `baseline_cpu_seconds`.
    cpu_seconds: f64,
    samples: u64,
}

impl ResourceSampler {
    /// `interval` is the delay between samples. `None` (or a zero interval)
    /// disables sampling entirely — the phase then reports zero samples, which
    /// is the honest "we did not observe this" answer.
    pub fn new(pid: u32, interval_ms: u64) -> Self {
        ResourceSampler {
            pid,
            interval: Duration::from_millis(interval_ms),
            peak_rss_bytes: 0,
            baseline_cpu_seconds: None,
            cpu_seconds: 0.0,
            samples: 0,
        }
    }

    /// Take one sample. A failure to read `/proc` is not an error — it just
    /// means that sample was not taken.
    pub fn sample(&mut self) {
        let Some(reading) = read_proc(self.pid) else {
            return;
        };
        self.observe(reading);
    }

    /// Fold one reading into the sampler.
    ///
    /// The first reading becomes the CPU baseline; every later reading
    /// publishes the CPU burned since that baseline — the CPU this phase
    /// actually cost. `peak_rss_bytes` stays a high-water mark: RSS does not
    /// accumulate, so the maximum across the phase's samples is the right
    /// summary and the pre-phase reading is a legitimate part of it.
    fn observe(&mut self, reading: ProcReading) {
        self.samples += 1;
        self.peak_rss_bytes = self.peak_rss_bytes.max(reading.rss_bytes);
        match self.baseline_cpu_seconds {
            None => self.baseline_cpu_seconds = Some(reading.cpu_seconds),
            Some(baseline) => {
                // A counter that went backwards would be a kernel artefact,
                // not a measurement — clamp it rather than publish a negative.
                self.cpu_seconds = (reading.cpu_seconds - baseline).max(0.0);
            }
        }
    }

    /// Sample once and then every `interval` until `stop` is signalled.
    ///
    /// The first sample is taken immediately, before the loop: it is the CPU
    /// baseline the phase's published figure is a difference from.
    ///
    /// Runs on a dedicated OS thread so the sampling cadence does not depend
    /// on the async runtime's scheduling — under load the tokio workers are
    /// busy issuing requests, and a sampler that got starved would report a
    /// peak RSS measured before the phase really started.
    pub fn spawn(
        mut self,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::thread::JoinHandle<Self> {
        std::thread::spawn(move || {
            if self.interval.is_zero() {
                return self;
            }
            self.sample();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(self.interval);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                self.sample();
            }
            self
        })
    }

    /// The observation, as published.
    ///
    /// `cpu_seconds` is the CPU burned since the sampler's first reading —
    /// the phase's own cost, not the process's lifetime CPU.
    pub fn usage(&self) -> crate::stats::ResourceUsage {
        crate::stats::ResourceUsage {
            peak_rss_bytes: self.peak_rss_bytes,
            cpu_seconds: self.cpu_seconds,
            samples: self.samples,
        }
    }
}

/// One reading of a process's CPU and memory.
struct ProcReading {
    rss_bytes: u64,
    /// Cumulative CPU seconds (user + system) the process has used since it
    /// started.
    cpu_seconds: f64,
}

/// Read `rss_bytes` and cumulative CPU seconds for `pid` from `/proc`.
///
/// Returns `None` when the process is gone or `/proc` is unavailable — the
/// caller treats that as "not sampled", never as zero.
fn read_proc(pid: u32) -> Option<ProcReading> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = parse_proc_stat(&stat)?;
    // `/proc/<pid>/stat` numbers its fields from 1, with the executable name
    // as field 2. The tail returned by `parse_proc_stat` starts at field 3
    // (`state`), so a 1-based field number `n` lives at tail index `n - 3`.
    //
    // - `rss` is field 24 → tail index 21. Reported in pages; the kernel's
    //   page size is 4 KiB on every architecture Linux supports today, and
    //   `/proc` reports RSS in pages by definition.
    // - `utime` is field 14 → tail index 11, `stime` is field 15 → index 12.
    //   Both are in clock ticks; `sysconf(_SC_CLK_TCK)` is 100 on every
    //   mainstream Linux configuration, so that is the documented constant we
    //   divide by.
    const RSS_FIELD_INDEX: usize = 21;
    const UTIME_FIELD_INDEX: usize = 11;
    const STIME_FIELD_INDEX: usize = 12;
    const PAGE_SIZE_BYTES: u64 = 4096;
    const CLOCK_TICKS_PER_SECOND: f64 = 100.0;

    let rss_bytes = fields.get(RSS_FIELD_INDEX).copied().unwrap_or(0.0) as u64 * PAGE_SIZE_BYTES;
    let utime = fields.get(UTIME_FIELD_INDEX).copied().unwrap_or(0.0);
    let stime = fields.get(STIME_FIELD_INDEX).copied().unwrap_or(0.0);
    let cpu_seconds = (utime + stime) / CLOCK_TICKS_PER_SECOND;

    Some(ProcReading {
        rss_bytes,
        cpu_seconds,
    })
}

/// Split after the last `)` and return the numeric fields *after* the
/// executable name.
///
/// The second field of `/proc/<pid>/stat` is the executable name in
/// parentheses and may itself contain spaces and parentheses
/// (`(my (weird) proc)`), so the split has to start *after* the last `)` —
/// not at the first space. Getting that wrong shifts every field after the
/// name, which would silently report the wrong RSS and CPU numbers.
///
/// The returned vector starts at field 3 (`state`); the field-number-to-index
/// mapping is documented on [`read_proc`].
fn parse_proc_stat(stat: &str) -> Option<Vec<f64>> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?;
    Some(
        rest.split_whitespace()
            .map(|f| f.parse::<f64>().unwrap_or(0.0))
            .collect(),
    )
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

    /// The phase must report a duration and a completed count that agree
    /// with the sample count — throughput is derived from them.
    #[tokio::test]
    async fn a_phase_reports_duration_and_completed_count() {
        let plan = Plan {
            concurrency: 2,
            requests: 20,
            warmup: 0,
        };
        let result = run_phase(Arc::new(Fixed(1.0)), Shape::PointLookup, plan)
            .await
            .expect("fixed path succeeds");
        assert_eq!(result.completed, 20);
        assert_eq!(result.summary.n as u64, result.completed);
        assert!(
            result.duration_ms > 0.0,
            "a phase that ran 20 requests cannot take zero time"
        );
        assert!(result.throughput().requests_per_sec > 0.0);
    }

    /// `/proc/<pid>/stat` puts the executable name in parentheses and the
    /// name may contain spaces. Splitting on the first space would shift
    /// every field and silently report the wrong RSS.
    #[test]
    fn proc_stat_is_split_after_the_executable_name() {
        let line = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194304 100 0 0 0 \
                    11 22 0 0 20 0 1 0 987 654321 100 18446744073709551615 \
                    1 1 2 3 4 5 6 7 8 9 10";
        let fields = parse_proc_stat(line).expect("parses");
        // `utime` is field 14 → index 11 in the tail; `stime` field 15 → 12.
        assert_eq!(fields.get(11), Some(&11.0), "utime misparsed: {fields:?}");
        assert_eq!(fields.get(12), Some(&22.0), "stime misparsed: {fields:?}");
    }

    #[test]
    fn proc_stat_of_a_live_process_reports_sane_numbers() {
        // The harness's own PID always exists.
        let pid = std::process::id();
        let Some(reading) = read_proc(pid) else {
            // A host without /proc — nothing to assert.
            return;
        };
        assert!(reading.rss_bytes > 0, "a live process has resident pages");
        assert!(reading.cpu_seconds >= 0.0);
    }

    #[test]
    fn a_missing_process_is_not_sampled_rather_than_zero() {
        // PID 0 is never a readable /proc entry on Linux.
        assert!(read_proc(0).is_none());
    }

    /// The published CPU figure must be the CPU burned *during the phase* —
    /// a difference from the first sample — not the process's lifetime
    /// counter. A lifetime counter would grow across phases and charge the
    /// phase for boot, for both baseline phases and for every earlier
    /// shape's gateway phase.
    #[test]
    fn cpu_seconds_is_the_delta_from_the_first_sample_not_the_lifetime_counter() {
        let mut sampler = ResourceSampler::new(std::process::id(), 0);
        sampler.observe(ProcReading {
            rss_bytes: 1024,
            cpu_seconds: 10.0,
        });
        // The first reading is the baseline: it establishes the phase's
        // starting CPU and contributes nothing to the delta.
        assert_eq!(
            sampler.usage().cpu_seconds,
            0.0,
            "the first sample is the baseline, not a phase cost"
        );
        sampler.observe(ProcReading {
            rss_bytes: 2048,
            cpu_seconds: 12.5,
        });
        assert_eq!(
            sampler.usage().cpu_seconds,
            2.5,
            "the published CPU must be the difference from the baseline"
        );
        // The peak RSS is a high-water mark, so the larger reading wins.
        assert_eq!(sampler.usage().peak_rss_bytes, 2048);
        assert_eq!(sampler.usage().samples, 2);
    }

    /// A counter that went backwards is a kernel artefact, not a measurement.
    /// Publishing a negative CPU cost would be nonsense, so it clamps to zero.
    #[test]
    fn a_cpu_counter_that_goes_backwards_clamps_to_zero() {
        let mut sampler = ResourceSampler::new(std::process::id(), 0);
        sampler.observe(ProcReading {
            rss_bytes: 1024,
            cpu_seconds: 5.0,
        });
        sampler.observe(ProcReading {
            rss_bytes: 1024,
            cpu_seconds: 4.0,
        });
        assert_eq!(sampler.usage().cpu_seconds, 0.0);
    }
}
