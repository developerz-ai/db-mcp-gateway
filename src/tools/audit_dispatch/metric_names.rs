//! Metric names emitted by the audit chokepoint.

/// Per-call counter — `tool` is the tool name, `outcome` is the spec 03 code
/// (`success`/`forbidden`/`timeout`/…). Both labels are bounded.
pub(super) const TOOL_CALLS: &str = "tool_calls";
/// Wall-clock the tool's own work took (from the `Outcome.elapsed_ms` the tool
/// reports). Excludes the audit write — that has its own histogram.
pub(super) const QUERY_DURATION: &str = "query_duration_seconds";
/// Wall-clock the synchronous audit insert took. Spec calls audit-write a
/// hot-path concern; this is the metric the alert in #22 will fire on.
pub(super) const AUDIT_WRITE_DURATION: &str = "audit_write_duration_seconds";
