//! Metric names emitted by the audit chokepoint.

/// Per-call counter — `tool` is the tool name, `outcome` is the spec 03 code
/// the client saw (`success`/`forbidden`/`audit_unavailable`/…), `access` is
/// `read`, `write`, or [`ACCESS_UNKNOWN`]. All labels are bounded.
pub(super) const TOOL_CALLS: &str = "tool_calls";
/// Wall-clock the tool's own work took (from the `Outcome.elapsed_ms` the tool
/// reports). Excludes the audit write — that has its own histogram.
pub(super) const QUERY_DURATION: &str = "query_duration_seconds";
/// Wall-clock the synchronous audit insert took. Spec calls audit-write a
/// hot-path concern; this is the metric the alert in #22 will fire on.
pub(super) const AUDIT_WRITE_DURATION: &str = "audit_write_duration_seconds";
/// Drop-guard fallback writes that failed: a call whose row may be missing
/// unless its intent row is reaped.
pub(super) const AUDIT_FALLBACK_FAILURES: &str = "audit_fallback_failures_total";
/// `access` label of a call dropped before its tool decided read vs write.
pub(super) const ACCESS_UNKNOWN: &str = "unknown";
