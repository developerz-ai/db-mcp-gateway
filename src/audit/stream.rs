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

    /// Spec 07 §Fields lists every field the audit log must carry. The stream
    /// is an SIEM-facing mirror of that row, so every listed field must land
    /// in the emitted event — a partial mirror forces consumers back into the
    /// state DB. Pin the JSON shape so a future edit that drops (say)
    /// `agent_client` or `groups` fails here before it reaches operators.
    #[test]
    fn stdout_sink_emits_every_spec_07_field() {
        let buf = BufWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_target(true)
            .finish();

        let mut row = sample_row();
        row.agent_client = Some("mcp-cli/1.2".into());
        row.ip = Some("10.0.0.5".into());
        row.reason = Some("incident-42".into());

        tracing::subscriber::with_default(subscriber, || {
            send(&[StreamSinkConfig::Stdout], &row);
        });

        let raw = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line = raw.lines().next().expect("subscriber emitted a line");
        let log: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("event is not JSON: {err}\nline: {line}"));

        assert_eq!(log["target"].as_str(), Some("audit_stream"));
        assert_eq!(log["message"].as_str(), Some("audit row streamed"));
        // Every persisted field from spec 07 §Fields.
        assert_eq!(log["audit_id"].as_str(), Some(row.id.to_string().as_str()));
        assert_eq!(log["request_id"].as_str(), Some("req-stream-1"));
        assert_eq!(log["user_sub"].as_str(), Some("user-1"));
        assert_eq!(log["user_email"].as_str(), Some("u@example.com"));
        assert_eq!(log["groups"].as_str(), Some(r#"["engineers"]"#));
        assert_eq!(log["tool"].as_str(), Some("run_query"));
        assert_eq!(log["server"].as_str(), Some("prod"));
        assert_eq!(log["database"].as_str(), Some("app"));
        assert_eq!(log["sql"].as_str(), Some("SELECT 1"));
        assert_eq!(log["reason"].as_str(), Some("incident-42"));
        assert_eq!(log["outcome"].as_str(), Some("success"));
        assert_eq!(log["elapsed_ms"].as_i64(), Some(4));
        assert_eq!(log["row_count"].as_i64(), Some(1));
        assert_eq!(log["truncated"].as_bool(), Some(false));
        assert_eq!(log["error_message"].as_str(), Some(""));
        assert_eq!(log["agent_client"].as_str(), Some("mcp-cli/1.2"));
        assert_eq!(log["ip"].as_str(), Some("10.0.0.5"));
        assert_eq!(log["db_type"].as_str(), Some("postgres"));
    }
}
