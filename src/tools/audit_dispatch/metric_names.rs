//! Metric names emitted by the audit chokepoint, and the bounded labels a
//! dispatch's call metrics carry.

use metrics::{counter, histogram};

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
/// Panics caught and answered `internal`; `layer` is `tool_work` here.
pub(super) const HANDLER_PANICS: &str = "handler_panics_total";
/// `access` label of a call dropped before its tool decided read vs write.
pub(super) const ACCESS_UNKNOWN: &str = "unknown";

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
