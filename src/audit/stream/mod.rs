//! Stream sinks (spec 07 §Storage "Stream" tier): fire-and-forget export of
//! every audit row, additional to — never instead of — the mandatory hot-tier
//! Postgres write. A sink outage must never fail an agent's request; only
//! `audit::log`'s synchronous write does that (CLAUDE.md non-negotiable #4).
//!
//! Callers invoke [`StreamSinks::send`] only after the durable write has
//! already succeeded (see `tools::audit_dispatch`) — a row that isn't yet the
//! system of record must not be streamed as if it were.
//!
//! Payload: the row is streamed as-is, matching the durable `audit_calls`
//! row field-for-field, so no sink can silently drift into a different field
//! list. The one exception is size: syslog cuts an oversized row to fit one
//! message, with a marker (see `syslog`). Every row reaches the sinks: tool
//! completions from `tools::audit_dispatch`, `abandoned` rows from
//! `audit::reaper`.

mod syslog;

use std::path::Path;
use std::sync::Arc;

use super::AuditRow;
use super::drain::DetachedTasks;
use crate::config::{StreamSinkConfig, SyslogTransportKind};
use syslog::SyslogSink;
pub use syslog::{SyslogTls, SyslogTlsError, SyslogTransport};

/// Counter: rows a sink failed to deliver. Label `sink` is the sink kind.
const STREAM_DROPPED: &str = "audit_stream_dropped_total";

/// The configured sinks, built once at boot so network sinks can keep their
/// resolved address and socket across rows. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct StreamSinks(Arc<[Sink]>);

#[derive(Debug)]
enum Sink {
    Stdout,
    Syslog(Arc<SyslogSink>),
}

impl StreamSinks {
    /// Build the configured sinks. Fails only on a TLS syslog sink whose
    /// `ca_file` is missing, unreadable or holds no usable CA — at boot and on
    /// a reload, never per row.
    pub fn from_config(config: &[StreamSinkConfig]) -> Result<Self, SyslogTlsError> {
        let sinks = config
            .iter()
            .map(|sink| match sink {
                StreamSinkConfig::Stdout => Ok(Sink::Stdout),
                StreamSinkConfig::Syslog {
                    host,
                    port,
                    transport,
                    ca_file,
                } => Ok(Sink::Syslog(Arc::new(SyslogSink::new(
                    host.clone(),
                    *port,
                    syslog_transport(*transport, ca_file.as_deref())?,
                )))),
            })
            .collect::<Result<Vec<Sink>, SyslogTlsError>>()?;
        Ok(Self(sinks.into()))
    }

    /// A single syslog sink on `transport`.
    pub fn syslog(host: String, port: u16, transport: SyslogTransport) -> Self {
        Self(Arc::new([Sink::Syslog(Arc::new(SyslogSink::new(
            host, port, transport,
        )))]))
    }

    /// Fan `row` out to every sink. `stdout` is a local `tracing` emission;
    /// `syslog` touches the network, so its delivery runs on `tasks` and this
    /// returns immediately either way.
    pub fn send(&self, row: &AuditRow, tasks: &DetachedTasks) {
        for sink in self.0.iter() {
            match sink {
                Sink::Stdout => send_stdout(row),
                Sink::Syslog(syslog) => syslog.spawn_delivery(row, tasks),
            }
        }
    }
}

fn syslog_transport(
    kind: SyslogTransportKind,
    ca_file: Option<&Path>,
) -> Result<SyslogTransport, SyslogTlsError> {
    match (kind, ca_file) {
        (SyslogTransportKind::Udp, _) => Ok(SyslogTransport::Udp),
        (SyslogTransportKind::Tcp, _) => Ok(SyslogTransport::Tcp),
        (SyslogTransportKind::Tls, Some(ca)) => {
            Ok(SyslogTransport::Tls(SyslogTls::from_ca_file(ca)?))
        }
        (SyslogTransportKind::Tls, None) => Err(SyslogTlsError::NoCaFile),
    }
}

/// Distinct `target` so operators can route this separately from the
/// gateway's own operational logs (the "tool dispatched" summary line in
/// `audit_dispatch` carries a narrower field set and is not a substitute —
/// spec 07: "the stdout log ... MUST NOT be the only place a tool call
/// leaves a trace"). `Option` fields flatten the same way the summary line
/// already does, rather than Debug-formatting `Some`/`None` — except
/// `rows_affected`, which is left out for a read: `0` is a real write count.
/// Every `AuditRow` field must land here (pinned by `parity_tests`) — SIEM
/// ingesters correlate the streamed event to the durable `audit_calls` row
/// by `audit_id`, so a partial mirror would leave consumers reaching back
/// into the state DB.
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
        upstream_actor = row.upstream_actor.as_deref().unwrap_or(""),
        upstream_run_id = row.upstream_run_id.as_deref().unwrap_or(""),
        rows_affected = row.rows_affected,
        sql_truncated = row.sql_truncated,
        "audit row streamed"
    );
}

#[cfg(test)]
mod parity_tests;
#[cfg(test)]
mod tests;
