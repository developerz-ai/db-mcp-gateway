//! `audit_failure_recent`: whether an audit write failed lately, judged by
//! this process on its monotonic clock. A pod first scraped after the failure
//! still shows it (a counter born above 0 has no `increase()`), and no wall
//! clock, the gateway's or Prometheus's, moves the window.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use metrics::gauge;

const AUDIT_FAILURE_RECENT: &str = "audit_failure_recent";
const WRITE_HOLD: Duration = Duration::from_secs(15 * 60);
const FALLBACK_HOLD: Duration = Duration::from_secs(30 * 60);

/// Which audit write failed: `Write` failed the request — a tool call
/// answered `audit_unavailable`, or an admin API request whose row could not
/// be written; `Fallback` is the drop-path retry.
#[derive(Debug, Clone, Copy)]
pub enum FailedAuditWrite {
    Write,
    Fallback,
}

#[derive(Debug)]
struct Hold {
    lasts: Duration,
    last_failure: ArcSwapOption<Instant>,
}

impl Hold {
    const fn new(lasts: Duration) -> Self {
        Self {
            lasts,
            last_failure: ArcSwapOption::const_empty(),
        }
    }

    /// Keep the newest failure: a thread preempted after reading its clock
    /// must not put an older one back.
    fn failed_at(&self, now: Instant) {
        self.last_failure.rcu(|last| match last {
            Some(last) if **last >= now => Arc::clone(last),
            _ => Arc::new(now),
        });
    }

    fn active_at(&self, now: Instant) -> bool {
        self.last_failure
            .load()
            .as_deref()
            .is_some_and(|last| now.saturating_duration_since(*last) < self.lasts)
    }
}

/// The last failure of each kind. Marking is lock-free, safe on the
/// request path; nothing expires it, [`AuditFailures::publish`] reads its age.
#[derive(Debug)]
pub struct AuditFailures {
    write: Hold,
    fallback: Hold,
}

impl AuditFailures {
    const fn new() -> Self {
        Self {
            write: Hold::new(WRITE_HOLD),
            fallback: Hold::new(FALLBACK_HOLD),
        }
    }

    /// Start, or restart, the hold of `kind`.
    pub fn mark(&self, kind: FailedAuditWrite) {
        self.mark_at(kind, Instant::now());
    }

    fn mark_at(&self, kind: FailedAuditWrite, now: Instant) {
        self.hold(kind).failed_at(now);
    }

    /// Set both gauges to their state now. Run before every scrape renders,
    /// so a value is never stale and never idles out of the recorder.
    pub fn publish(&self) {
        self.publish_at(Instant::now());
    }

    fn publish_at(&self, now: Instant) {
        for (kind, label) in [
            (FailedAuditWrite::Write, "write"),
            (FailedAuditWrite::Fallback, "fallback"),
        ] {
            let recent = self.hold(kind).active_at(now);
            gauge!(AUDIT_FAILURE_RECENT, "kind" => label).set(f64::from(u8::from(recent)));
        }
    }

    /// Forget every failure. The set is process-wide: a test that asserts a
    /// mark must first drop the ones other tests in its binary left.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reset(&self) {
        self.write.last_failure.store(None);
        self.fallback.last_failure.store(None);
    }

    #[cfg(test)]
    pub(super) fn is_recent(&self, kind: FailedAuditWrite) -> bool {
        self.hold(kind).active_at(Instant::now())
    }

    fn hold(&self, kind: FailedAuditWrite) -> &Hold {
        match kind {
            FailedAuditWrite::Write => &self.write,
            FailedAuditWrite::Fallback => &self.fallback,
        }
    }
}

/// This process's audit failures.
pub fn audit_failures() -> &'static AuditFailures {
    static FAILURES: AuditFailures = AuditFailures::new();
    &FAILURES
}

#[cfg(test)]
#[path = "failure_hold_tests.rs"]
mod tests;
