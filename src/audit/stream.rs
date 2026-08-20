//! Stream sinks (spec 07 §Storage "Stream" tier): fire-and-forget export of
//! every audit row, additional to — never instead of — the mandatory hot-tier
//! Postgres write. A sink outage must never fail an agent's request; only
//! `audit::log`'s synchronous write does that (CLAUDE.md non-negotiable #4).
//!
//! Callers invoke [`send`] only after the durable write has already
//! succeeded (see `tools::audit_dispatch`) — a row that isn't yet the system
//! of record must not be streamed as if it were.

use super::AuditRow;
use crate::config::StreamSinkConfig;

/// Fan `row` out to every configured sink. Synchronous but non-blocking in
/// practice: each sink here is a local `tracing` emission, not a network
/// call, so there's nothing to spawn or await yet. A future sink that does
/// hit the network (syslog, OTLP) must keep this contract — fire-and-forget,
/// logged on failure, never a delay or error the caller has to handle.
pub fn send(sinks: &[StreamSinkConfig], row: &AuditRow) {
    for sink in sinks {
        match sink {
            StreamSinkConfig::Stdout => send_stdout(row),
        }
    }
}

/// Distinct `target` so operators can route this separately from the
/// gateway's own operational logs (the "tool dispatched" summary line in
/// `audit_dispatch` carries a narrower field set and is not a substitute —
/// spec 07: "the stdout log ... MUST NOT be the only place a tool call
/// leaves a trace"). `Option` fields flatten the same way the summary line
/// already does, rather than Debug-formatting `Some`/`None`.
fn send_stdout(row: &AuditRow) {
    tracing::info!(
        target: "audit_stream",
        request_id = %row.request_id,
        user_sub = %row.user_sub,
        user_email = %row.user_email,
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
        db_type = row.db_type.as_deref().unwrap_or(""),
        "audit row streamed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;
    use uuid::Uuid;

    #[derive(Clone, Default)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn sample_row() -> AuditRow {
        AuditRow {
            id: Uuid::new_v4(),
            request_id: "req-stream-1".into(),
            user_sub: "user-1".into(),
            user_email: "u@example.com".into(),
            groups: vec!["engineers".into()],
            tool: "run_query".into(),
            server: Some("prod".into()),
            database: Some("app".into()),
            sql: Some("SELECT 1".into()),
            reason: None,
            outcome: "success".into(),
            elapsed_ms: Some(4),
            row_count: Some(1),
            truncated: Some(false),
            error_message: None,
            agent_client: None,
            ip: None,
            db_type: Some("postgres".into()),
        }
    }

    /// No sinks configured → no-op. The common case (pre-#218 default).
    #[test]
    fn empty_sinks_is_a_no_op() {
        send(&[], &sample_row());
    }

    /// The `stdout` sink emits one `audit_stream`-targeted event carrying the
    /// row's identifying fields — this is the wire contract operators build
    /// SIEM ingestion against, so pin it.
    #[test]
    fn stdout_sink_emits_audit_stream_event_with_row_fields() {
        let buf = BufWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            send(&[StreamSinkConfig::Stdout], &sample_row());
        });

        let output = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("audit_stream"), "{output}");
        assert!(output.contains("req-stream-1"), "{output}");
        assert!(output.contains("run_query"), "{output}");
        assert!(output.contains("success"), "{output}");
        assert!(output.contains("SELECT 1"), "{output}");
    }
}
