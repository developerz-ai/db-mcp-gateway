//! Metric names emitted by the audit chokepoint, and the bounded labels a
//! dispatch's call metrics carry.

use std::time::{SystemTime, UNIX_EPOCH};

use metrics::{counter, gauge, histogram};

use crate::audit::OutcomeCode;
use crate::config::ConfigFile;

use super::AuditHeader;

/// Per-call counter — `tool` is the tool name, `outcome` is the spec 03 code
/// the client saw (`success`/`forbidden`/`audit_unavailable`/…), `access` is
/// `read`, `write`, or [`ACCESS_UNKNOWN`]. All labels are bounded.
pub(super) const TOOL_CALLS: &str = "tool_calls";
/// [`TOOL_CALLS`] per configured database instead of per tool: two
/// counters, not one with both labels, so neither multiplies the other.
const TOOL_CALLS_BY_DB: &str = "tool_calls_by_db";
/// Wall-clock the tool's own work took (from the `Outcome.elapsed_ms` the tool
/// reports). Excludes the audit write — that has its own histogram.
const QUERY_DURATION: &str = "query_duration_seconds";
/// Wall-clock the synchronous audit insert took. Spec calls audit-write a
/// hot-path concern; this is the metric the alert in #22 will fire on.
pub(super) const AUDIT_WRITE_DURATION: &str = "audit_write_duration_seconds";
/// Drop-guard fallback writes that failed: a call whose row may be missing
/// unless its intent row is reaped.
pub(super) const AUDIT_FALLBACK_FAILURES: &str = "audit_fallback_failures_total";
/// Unix seconds of the last audit write that failed, by `kind`: alerts read
/// how recent it is, which a pod first scraped after the failure still shows
/// (a counter born above 0 has no `increase()`).
const AUDIT_LAST_FAILURE: &str = "audit_last_failure_timestamp";
/// Panics caught and answered `internal`; `layer` is `tool_work` here.
pub(super) const HANDLER_PANICS: &str = "handler_panics_total";
/// `access` label of a call dropped before its tool decided read vs write.
pub(super) const ACCESS_UNKNOWN: &str = "unknown";

/// Which audit write failed: [`FailedAuditWrite::Write`] answered the client
/// `audit_unavailable`; [`FailedAuditWrite::Fallback`] is the drop-path retry.
#[derive(Debug, Clone, Copy)]
pub(super) enum FailedAuditWrite {
    Write,
    Fallback,
}

/// Stamp `audit_last_failure_timestamp{kind}` with now.
pub(super) fn record_audit_failure(kind: FailedAuditWrite) {
    let kind = match kind {
        FailedAuditWrite::Write => "write",
        FailedAuditWrite::Fallback => "fallback",
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default();
    gauge!(AUDIT_LAST_FAILURE, "kind" => kind).set(now);
}

/// The labels of one dispatch's call metrics.
#[derive(Debug, Clone)]
pub(super) struct CallLabels {
    pub(super) tool: &'static str,
    /// `server/database` — the pool metrics' `db` — only when the call named
    /// a database the config holds. Caller text never becomes a label: an
    /// unknown name would add a series per guess.
    db: Option<String>,
}

impl CallLabels {
    /// Labels for a call measured with no config to bound its target by.
    pub(super) fn untargeted(tool: &'static str) -> Self {
        Self { tool, db: None }
    }

    pub(super) fn of(config: &ConfigFile, header: &AuditHeader<'_>) -> Self {
        let db = header.server.zip(header.database).and_then(|(server, db)| {
            config
                .servers
                .iter()
                .find(|s| s.name == server)?
                .databases
                .iter()
                .find(|d| d.name == db)
                .map(|_| format!("{server}/{db}"))
        });
        Self {
            tool: header.tool,
            db,
        }
    }

    /// Count one call: per tool always, per database when it named one.
    pub(super) fn count(&self, code: OutcomeCode, access: &'static str) {
        if code == OutcomeCode::AuditUnavailable {
            record_audit_failure(FailedAuditWrite::Write);
        }
        counter!(
            TOOL_CALLS,
            "tool" => self.tool,
            "outcome" => code.as_str(),
            "access" => access,
        )
        .increment(1);
        if let Some(db) = &self.db {
            counter!(
                TOOL_CALLS_BY_DB,
                "db" => db.clone(),
                "outcome" => code.as_str(),
                "access" => access,
            )
            .increment(1);
        }
    }

    /// `db` is empty for a call that named no configured database.
    pub(super) fn record_duration(&self, seconds: f64) {
        histogram!(
            QUERY_DURATION,
            "tool" => self.tool,
            "db" => self.db.clone().unwrap_or_default(),
        )
        .record(seconds);
    }
}

#[cfg(test)]
mod tests {
    use metrics_exporter_prometheus::PrometheusBuilder;

    use super::*;

    #[test]
    fn audit_unavailable_stamps_the_last_write_failure() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let labels = CallLabels::untargeted("run_query");
        metrics::with_local_recorder(&recorder, || {
            labels.count(OutcomeCode::Success, "read");
            labels.count(OutcomeCode::Forbidden, "read");
        });
        let body = recorder.handle().render();
        assert!(!body.contains(AUDIT_LAST_FAILURE), "{body}");

        metrics::with_local_recorder(&recorder, || {
            labels.count(OutcomeCode::AuditUnavailable, "read");
            record_audit_failure(FailedAuditWrite::Fallback);
        });
        let body = recorder.handle().render();
        for kind in ["write", "fallback"] {
            let line = body
                .lines()
                .find(|l| {
                    l.starts_with(&format!(
                        r#"audit_last_failure_timestamp{{kind="{kind}"}} "#
                    ))
                })
                .unwrap_or_else(|| panic!("no {kind} stamp:\n{body}"));
            let stamp: f64 = line
                .rsplit(' ')
                .next()
                .and_then(|v| v.parse().ok())
                .expect("value");
            assert!(stamp > 1.7e9, "{line}");
        }
    }
}
