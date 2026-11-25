//! The hold windows, and that a refused call starts the `write` one. The
//! guard's failed fallback is in `cancel_guard_tests.rs`.

use metrics_exporter_prometheus::PrometheusBuilder;

use super::*;
use crate::audit::OutcomeCode;
use crate::tools::audit_dispatch::metric_names::CallLabels;

/// `(write, fallback)` as a scrape at `now` renders them.
fn scraped(failures: &AuditFailures, now: Instant) -> (u8, u8) {
    let recorder = PrometheusBuilder::new().build_recorder();
    metrics::with_local_recorder(&recorder, || failures.publish_at(now));
    let body = recorder.handle().render();
    let value = |kind: &str| {
        let sample = format!(r#"audit_failure_recent{{kind="{kind}"}} "#);
        body.lines()
            .find_map(|line| line.strip_prefix(&sample))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("no {kind} sample:\n{body}"))
    };
    (value("write"), value("fallback"))
}

#[test]
fn both_kinds_are_exported_at_zero_before_any_failure() {
    assert_eq!(scraped(&AuditFailures::new(), Instant::now()), (0, 0));
}

#[test]
fn a_failure_shows_at_once_and_holds_for_its_own_window() {
    let failures = AuditFailures::new();
    let start = Instant::now();
    let after = |window: Duration| start + window;
    let tick = Duration::from_nanos(1);
    failures.mark_at(FailedAuditWrite::Write, start);
    assert_eq!(scraped(&failures, start), (1, 0));
    assert_eq!(scraped(&failures, after(WRITE_HOLD - tick)), (1, 0));
    assert_eq!(scraped(&failures, after(WRITE_HOLD)), (0, 0));

    failures.mark_at(FailedAuditWrite::Fallback, start);
    assert_eq!(scraped(&failures, after(WRITE_HOLD)), (0, 1));
    assert_eq!(scraped(&failures, after(FALLBACK_HOLD - tick)), (0, 1));
    assert_eq!(scraped(&failures, after(FALLBACK_HOLD)), (0, 0));
}

#[test]
fn a_new_failure_restarts_the_window_during_and_after_a_hold() {
    let failures = AuditFailures::new();
    let first = Instant::now();
    failures.mark_at(FailedAuditWrite::Write, first);
    let second = first + WRITE_HOLD - Duration::from_secs(1);
    failures.mark_at(FailedAuditWrite::Write, second);
    assert_eq!(scraped(&failures, first + WRITE_HOLD), (1, 0));
    assert_eq!(scraped(&failures, second + WRITE_HOLD), (0, 0));

    let third = second + WRITE_HOLD * 4;
    failures.mark_at(FailedAuditWrite::Write, third);
    assert_eq!(scraped(&failures, third), (1, 0));
    assert_eq!(scraped(&failures, third + WRITE_HOLD), (0, 0));
}

/// The only test in this binary that marks the process-wide `write` hold.
#[test]
fn only_a_call_answered_audit_unavailable_starts_the_write_hold() {
    let labels = CallLabels::untargeted("run_query");
    for code in [
        OutcomeCode::Success,
        OutcomeCode::Forbidden,
        OutcomeCode::Unavailable,
        OutcomeCode::Internal,
        OutcomeCode::Cancelled,
    ] {
        labels.count(code, "read");
    }
    assert!(!audit_failures().is_recent(FailedAuditWrite::Write));
    labels.count(OutcomeCode::AuditUnavailable, "read");
    assert!(audit_failures().is_recent(FailedAuditWrite::Write));
}
