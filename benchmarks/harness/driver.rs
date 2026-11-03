//! Closed-loop load driver.
//!
//! `concurrency` workers each pull the next iteration number off a shared
//! counter and issue one request, until `requests` have been issued. Closed
//! loop — a worker's next request starts only when its previous one finishes —
//! which is what an agent fleet actually does, and unlike an open-loop
//! generator it cannot produce a coordinated-omission artefact by queueing
//! requests the system never accepted.

use std::collections::BTreeMap;
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
    /// The raw per-request latencies, in milliseconds, **unsorted**, in
    /// global completion order.
    ///
    /// Completion order — not worker-join order: every completed request is
    /// stamped with a global completion counter and the samples are merged
    /// on that stamp before publication. With `concurrency > 1` the sequence
    /// is the order the requests actually finished in, so a slow patch
    /// visible in the middle of the run is where the run's slowness was, not
    /// an artefact of which worker happened to hold which samples.
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
    // Global completion sequence: each completed request claims the next
    // value, and the samples are merged on it afterwards. Without the stamp,
    // sequential joins would concatenate each worker's samples in join order
    // — the order workers *finish*, not the order their requests did.
    let completion = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::with_capacity(plan.concurrency as usize);

    for _ in 0..plan.concurrency.max(1) {
        let path = Arc::clone(&path);
        let counter = Arc::clone(&counter);
        let completion = Arc::clone(&completion);
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
                    Ok(ms) => {
                        let order = completion.fetch_add(1, Ordering::Relaxed);
                        samples.push((order, ms));
                    }
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

    let mut stamped = Vec::with_capacity(plan.requests as usize);
    let mut errors = 0u64;
    let mut first_error = None;
    for worker in workers {
        let (samples, worker_errors, worker_first) = worker
            .await
            .map_err(|e| format!("load worker panicked: {e}"))?;
        stamped.extend(samples);
        errors += worker_errors;
        if first_error.is_none() {
            first_error = worker_first;
        }
    }

    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;

    // Merge on the completion stamp so the published sequence is the global
    // completion order (see `samples_ms`).
    stamped.sort_unstable_by_key(|(order, _)| *order);
    let all: Vec<f64> = stamped.into_iter().map(|(_, ms)| ms).collect();

    let completed = all.len() as u64;
    // `Summary::from_samples` sorts in place, which would destroy the
    // completion order. The summary is computed from a clone so the raw
    // samples keep the order they completed in — the order is what
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

/// Samples the gateway processes' CPU and memory from `/proc`.
///
/// The gateway is the process under test, so its own resource usage is what
/// the "resource utilization under load" section reports. One sampler covers
/// the whole fleet of gateway PIDs the runner started: every observation
/// reads each process in turn and *sums* their RSS, so the published peak is
/// the fleet's high-water memory — the largest single process would
/// under-report exactly the multi-instance runs the scaling phase cares
/// about. Reading `/proc` directly keeps the harness dependency-free and
/// works on any Linux host; on a host without `/proc` every sample simply
/// fails and the phase is reported as unobserved rather than as zero.
///
/// Deliberately *not* a `tokio` task reading the files repeatedly: each
/// sample is a blocking file read of a few hundred bytes, and the harness is
/// a load generator — a few extra syscalls per sample are noise next to the
/// gateway's own work, but a blocking read on the async runtime's worker
/// threads would not be.
pub struct ResourceSampler {
    pids: Vec<u32>,
    interval: Duration,
    /// Peak of the per-observation **sums** across the fleet — not the
    /// largest single process.
    peak_rss_bytes: u64,
    /// Cumulative CPU at each process's first reading — the per-process
    /// baseline the published phase figure is measured against.
    ///
    /// `/proc` reports CPU since the process *started*, so publishing that
    /// number as "the CPU burned during this phase" would charge the phase
    /// for boot, for both baseline phases and for every earlier shape's
    /// gateway phase. The first reading per process is therefore taken as
    /// that process's baseline and only the differences — summed across the
    /// fleet — are published.
    baselines: BTreeMap<u32, f64>,
    /// CPU seconds each process has burned since its own baseline.
    cpu_by_pid: BTreeMap<u32, f64>,
    samples: u64,
}

impl ResourceSampler {
    /// `interval` is the delay between observations of the whole fleet. A
    /// zero interval disables sampling entirely — the phase then reports
    /// zero samples, which is the honest "we did not observe this" answer.
    pub fn new(pids: Vec<u32>, interval_ms: u64) -> Self {
        ResourceSampler {
            pids,
            interval: Duration::from_millis(interval_ms),
            peak_rss_bytes: 0,
            baselines: BTreeMap::new(),
            cpu_by_pid: BTreeMap::new(),
            samples: 0,
        }
    }

    /// Take one observation of every process in the fleet. A failure to read
    /// `/proc` is not an error — it just means that sample was not taken. A
    /// process that has gone missing is skipped; the rest of the fleet is
    /// still observed in the same round.
    pub fn sample(&mut self) {
        let mut round_rss_bytes = 0u64;
        let mut observed = 0usize;
        // Indexed so `observe` can borrow `self` mutably while the pid list
        // is only read.
        for index in 0..self.pids.len() {
            let pid = self.pids[index];
            let Some(reading) = read_proc(pid) else {
                continue;
            };
            observed += 1;
            round_rss_bytes += self.observe(pid, reading);
        }
        self.close_round(observed, round_rss_bytes);
    }

    /// Fold one reading into the sampler, returning its RSS for the round
    /// sum.
    ///
    /// The first reading for a process becomes its CPU baseline; every later
    /// reading publishes the CPU burned since that baseline — the CPU this
    /// phase actually cost. `peak_rss_bytes` stays a high-water mark over the
    /// per-round fleet sums: RSS does not accumulate, so the maximum across
    /// the phase's observations is the right summary, and the pre-phase
    /// reading is a legitimate part of it.
    fn observe(&mut self, pid: u32, reading: ProcReading) -> u64 {
        match self.baselines.get(&pid) {
            None => {
                self.baselines.insert(pid, reading.cpu_seconds);
                self.cpu_by_pid.insert(pid, 0.0);
            }
            Some(baseline) => {
                // A counter that went backwards would be a kernel artefact,
                // not a measurement — clamp it rather than publish a negative.
                self.cpu_by_pid
                    .insert(pid, (reading.cpu_seconds - baseline).max(0.0));
            }
        }
        reading.rss_bytes
    }

    /// Close one observation round. A round in which no process answered is
    /// not an observation — it must not count a sample or plant a zero peak.
    fn close_round(&mut self, observed: usize, round_rss_bytes: u64) {
        if observed == 0 {
            return;
        }
        self.samples += 1;
        self.peak_rss_bytes = self.peak_rss_bytes.max(round_rss_bytes);
    }

    /// Sample the fleet once and then every `interval` until `stop` is
    /// signalled.
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
    /// `cpu_seconds` is the CPU burned since each process's first reading,
    /// summed across the fleet — the phase's own cost, not lifetime
    /// counters. `peak_rss_bytes` is the largest per-round sum — the fleet's
    /// peak memory, not its biggest member's.
    pub fn usage(&self) -> crate::stats::ResourceUsage {
        crate::stats::ResourceUsage {
            peak_rss_bytes: self.peak_rss_bytes,
            cpu_seconds: self.cpu_by_pid.values().sum(),
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
/// RSS comes from `/proc/<pid>/status`'s `VmRSS:` line — the kernel renders
/// it in kB, so no page-size constant is involved. (`/proc/<pid>/stat`
/// reports RSS in *pages*; multiplying by a hardcoded 4096 would understate
/// memory fourfold on a 16 KiB-page host and sixteenfold on a 64 KiB-page
/// host, both of which exist on arm64.) CPU comes from `stat`'s `utime` and
/// `stime`, in clock ticks; `sysconf(_SC_CLK_TCK)` is 100 on every
/// mainstream Linux configuration, so that is the documented constant we
/// divide by.
///
/// Returns `None` when the process is gone or `/proc` is unavailable — the
/// caller treats that as "not sampled", never as zero.
fn read_proc(pid: u32) -> Option<ProcReading> {
    // `status` first: a process that vanishes between the two reads fails
    // here half the time, which is the "not sampled" case anyway.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_bytes = parse_vm_rss_bytes(&status)?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = parse_proc_stat(&stat)?;
    // `/proc/<pid>/stat` numbers its fields from 1, with the executable name
    // as field 2. The tail returned by `parse_proc_stat` starts at field 3
    // (`state`), so a 1-based field number `n` lives at tail index `n - 3`:
    // `utime` is field 14 → tail index 11, `stime` is field 15 → index 12.
    // Both are in clock ticks (see the CPU note above).
    const UTIME_FIELD_INDEX: usize = 11;
    const STIME_FIELD_INDEX: usize = 12;
    const CLOCK_TICKS_PER_SECOND: f64 = 100.0;

    let utime = fields.get(UTIME_FIELD_INDEX).copied().unwrap_or(0.0);
    let stime = fields.get(STIME_FIELD_INDEX).copied().unwrap_or(0.0);

    Some(ProcReading {
        rss_bytes,
        cpu_seconds: (utime + stime) / CLOCK_TICKS_PER_SECOND,
    })
}

/// `VmRSS:` from a `/proc/<pid>/status`, in bytes.
///
/// The kernel renders the line in kB (its kB — 1024 bytes), which is why
/// this conversion needs no assumption about the host's page size. `None`
/// when the line is absent.
fn parse_vm_rss_bytes(status: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kb: u64 = line
        .strip_prefix("VmRSS:")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kb * 1024)
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

    /// Unevenly spaced sleeps: each later iteration is shorter, but not by a
    /// constant. An evenly spaced ladder (`120/90/60/30`) ties its last two
    /// completions — `d1 + d2 == d0 + d3` holds for any arithmetic sequence —
    /// and which of two timers expiring at the same instant fires first is the
    /// scheduler's coin flip, not the fixture's. The gaps below keep every
    /// completion instant distinct by ≥40 ms.
    struct SleepsByIteration;

    #[async_trait]
    impl Path for SleepsByIteration {
        async fn run(&self, _shape: Shape, iteration: u64) -> Result<f64, String> {
            let ms = match iteration {
                0 => 160,
                1 => 60,
                2 => 140,
                _ => 80,
            };
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(ms as f64)
        }
        fn label(&self) -> &'static str {
            "sleeps-by-iteration"
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
    /// every field and silently report the wrong CPU.
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

    /// RSS must come from the kernel's own kB rendering, not from pages
    /// times an assumed page size — a hardcoded 4096 would understate
    /// memory fourfold on a 16 KiB-page host and sixteenfold on a 64 KiB-page
    /// host, both of which exist on arm64.
    #[test]
    fn vm_rss_is_parsed_from_the_kernel_rendering_in_bytes() {
        let status = "Name:\tgate\nVmRSS:\t   1234 kB\nVmSize:\t 9999 kB\n";
        assert_eq!(parse_vm_rss_bytes(status), Some(1234 * 1024));
        // A status without the line (or an unparseable one) is not sampled,
        // not zero.
        assert_eq!(parse_vm_rss_bytes("Name:\tgate\n"), None);
        assert_eq!(parse_vm_rss_bytes("VmRSS:\tnot-a-number kB\n"), None);
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
        let mut sampler = ResourceSampler::new(vec![std::process::id()], 0);
        // The first reading is the baseline: it establishes the phase's
        // starting CPU and contributes nothing to the delta.
        assert_eq!(
            sampler.observe(
                42,
                ProcReading {
                    rss_bytes: 1024,
                    cpu_seconds: 10.0
                }
            ),
            1024,
            "the reading's RSS feeds the round sum"
        );
        assert_eq!(
            sampler.usage().cpu_seconds,
            0.0,
            "the first sample is the baseline, not a phase cost"
        );
        assert_eq!(
            sampler.observe(
                42,
                ProcReading {
                    rss_bytes: 2048,
                    cpu_seconds: 12.5
                }
            ),
            2048,
        );
        assert_eq!(
            sampler.usage().cpu_seconds,
            2.5,
            "the published CPU must be the difference from the baseline"
        );
        // Nothing is a sample until its round closes.
        assert_eq!(sampler.usage().samples, 0);
        sampler.close_round(2, 1024 + 2048);
        assert_eq!(sampler.usage().samples, 1);
        assert_eq!(sampler.usage().peak_rss_bytes, 1024 + 2048);
    }

    /// A counter that went backwards is a kernel artefact, not a measurement.
    /// Publishing a negative CPU cost would be nonsense, so it clamps to zero.
    #[test]
    fn a_cpu_counter_that_goes_backwards_clamps_to_zero() {
        let mut sampler = ResourceSampler::new(vec![std::process::id()], 0);
        sampler.observe(
            42,
            ProcReading {
                rss_bytes: 1024,
                cpu_seconds: 5.0,
            },
        );
        sampler.observe(
            42,
            ProcReading {
                rss_bytes: 1024,
                cpu_seconds: 4.0,
            },
        );
        assert_eq!(sampler.usage().cpu_seconds, 0.0);
    }

    /// The published peak must be the fleet's memory — the per-observation
    /// sum — not the largest single process. A max-per-process merge would
    /// report 2048 here; the fleet peaked at 3100.
    #[test]
    fn peak_rss_is_the_fleet_sum_not_the_largest_single_process() {
        let mut sampler = ResourceSampler::new(vec![1, 2], 0);
        let mut round = 0u64;
        round += sampler.observe(
            1,
            ProcReading {
                rss_bytes: 1024,
                cpu_seconds: 0.0,
            },
        );
        round += sampler.observe(
            2,
            ProcReading {
                rss_bytes: 2048,
                cpu_seconds: 0.0,
            },
        );
        sampler.close_round(2, round);

        // A later round where both processes grew: the sum exceeds every
        // individual process's own peak.
        let mut round = 0u64;
        round += sampler.observe(
            1,
            ProcReading {
                rss_bytes: 1500,
                cpu_seconds: 1.0,
            },
        );
        round += sampler.observe(
            2,
            ProcReading {
                rss_bytes: 1600,
                cpu_seconds: 1.0,
            },
        );
        sampler.close_round(2, round);

        assert_eq!(
            sampler.usage().peak_rss_bytes,
            1500 + 1600,
            "the peak is the fleet's summed RSS, not the biggest process"
        );
        // CPU is the sum of each process's delta from its own baseline.
        assert_eq!(sampler.usage().cpu_seconds, 2.0);
        assert_eq!(sampler.usage().samples, 2);
    }

    /// One dead PID must not void the round: the live processes are still
    /// observed, and the round still counts as a sample.
    #[test]
    fn a_dead_process_is_skipped_and_the_live_one_still_counts() {
        // PID 0 has no /proc entry; the second PID is this test process.
        let mut sampler = ResourceSampler::new(vec![0, std::process::id()], 0);
        sampler.sample();
        assert_eq!(sampler.usage().samples, 1);
        assert!(sampler.usage().peak_rss_bytes > 0);
        assert!(sampler.usage().cpu_seconds >= 0.0);
    }

    /// samples_ms must be in global completion order. With concurrency 2 and
    /// per-iteration sleeps of 160/60/140/80 ms: iteration 1 finishes at
    /// 60 ms, its worker takes iteration 2 (finishes at 200 ms) while the
    /// other worker is still in iteration 0 (finishes at 160 ms), which then
    /// takes iteration 3 (finishes at 240 ms). Iterations 1, 0, 2, 3 finish
    /// in that order — interleaved across the two workers, which worker-join
    /// concatenation cannot produce: it would publish [60, 140, 160, 80],
    /// never this.
    #[tokio::test]
    async fn samples_are_published_in_global_completion_order() {
        let plan = Plan {
            concurrency: 2,
            requests: 4,
            warmup: 0,
        };
        let result = run_phase(Arc::new(SleepsByIteration), Shape::PointLookup, plan)
            .await
            .expect("path succeeds");
        assert_eq!(
            result.samples_ms,
            vec![60.0, 160.0, 140.0, 80.0],
            "the published sequence must be the completion order"
        );
    }
}
