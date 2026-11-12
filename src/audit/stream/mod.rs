//! Stream sinks (spec 07 §Storage "Stream" tier): fire-and-forget export of
//! every audit row, additional to — never instead of — the mandatory hot-tier
//! Postgres write. A sink outage must never fail an agent's request; only
//! `audit::log`'s synchronous write does that (CLAUDE.md non-negotiable #4).
//!
//! Callers invoke [`send`] only after the durable write has already
//! succeeded (see `tools::audit_dispatch`) — a row that isn't yet the system
//! of record must not be streamed as if it were.
//!
//! Payload: the row is streamed as-is, matching the durable `audit_calls`
//! row byte-for-byte. Redaction (`sql_capture: redacted | metadata_only`)
//! is a per-database policy applied at the audit-row layer (spec 07/08),
//! not per-sink — so `stdout`, `syslog`, and the durable row all see the
//! same policy-redacted `sql`, and no sink can silently drift into a
//! different field list.

mod syslog;

use super::AuditRow;
use crate::config::StreamSinkConfig;
use syslog::send_syslog;

/// Fan `row` out to every configured sink. `stdout` is a local `tracing`
/// emission — nothing to spawn. `syslog` touches the network (DNS + a UDP
/// send), so it spawns a detached task: this function returns immediately
/// either way, keeping the fire-and-forget contract callers rely on.
pub fn send(sinks: &[StreamSinkConfig], row: &AuditRow) {
    for sink in sinks {
        match sink {
            StreamSinkConfig::Stdout => send_stdout(row),
            StreamSinkConfig::Syslog { host, port } => send_syslog(host, *port, row),
        }
    }
}

/// Distinct `target` so operators can route this separately from the
/// gateway's own operational logs (the "tool dispatched" summary line in
/// `audit_dispatch` carries a narrower field set and is not a substitute —
/// spec 07: "the stdout log ... MUST NOT be the only place a tool call
/// leaves a trace"). `Option` fields flatten the same way the summary line
/// already does, rather than Debug-formatting `Some`/`None`. Every field
/// listed in spec 07 §Fields must land here — SIEM ingesters correlate the
/// streamed event to the durable `audit_calls` row by `audit_id`, so a
/// partial mirror would leave consumers reaching back into the state DB.
fn send_stdout(row: &AuditRow) {
    // JSON-serialize the group snapshot so the emitted field is a valid
    // JSON array string, matching the JSONB shape in `audit_calls.groups`.
    // `unwrap_or_default()` reduces to `""` if serialization ever fails —
    // which cannot happen for `Vec<String>` — but keeps the log line valid
    // rather than crashing the fire-and-forget path.
    let groups = serde_json::to_string(&row.groups).unwrap_or_default();
    tracing::info!(
        target: "audit_stream",
        audit_id = %row.id,
        request_id = %row.request_id,
        user_sub = %row.user_sub,
        user_email = %row.user_email,
        groups = %groups,
        tool = %row.tool,
        server = row.server.as_deref().unwrap_or(""),
        database = row.database.as_deref().unwrap_or(""),
        sql = row.sql.as_deref().unwrap_or(""),
        reason = row.reason.as_deref().unwrap_or(""),
        outcome = %row.outcome,
        elapsed_ms = row.elapsed_ms.unwrap_or(0),
        row_count = row.row_count.unwrap_or(0),
        truncated = row.truncated.unwrap_or(false),
        error_message = row.error_message.as_deref().unwrap_or(""),
        agent_client = row.agent_client.as_deref().unwrap_or(""),
        ip = row.ip.as_deref().unwrap_or(""),
        db_type = row.db_type.as_deref().unwrap_or(""),
        "audit row streamed"
    );
}

#[cfg(test)]
mod tests;
