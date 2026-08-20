//! Stream sinks (spec 07 §Storage "Stream" tier): fire-and-forget export of
//! every audit row, additional to — never instead of — the mandatory hot-tier
//! Postgres write. A sink outage must never fail an agent's request; only
//! `audit::log`'s synchronous write does that (CLAUDE.md non-negotiable #4).
//!
//! Callers invoke [`send`] only after the durable write has already
//! succeeded (see `tools::audit_dispatch`) — a row that isn't yet the system
//! of record must not be streamed as if it were.

use chrono::SecondsFormat;

use super::AuditRow;
use crate::config::StreamSinkConfig;

/// RFC 5424 PRI: `facility * 8 + severity`. `local0` (16) is the
/// conventional facility for application-generated audit/security events;
/// `informational` (6) matches "audit row streamed", not an error.
const SYSLOG_PRI: u8 = 16 * 8 + 6;
const SYSLOG_APP_NAME: &str = "db-mcp-gateway";

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

/// Format one audit row as an RFC 5424 syslog message, MSG body = the row
/// as JSON (same data the durable `audit_calls` row holds — see
/// [`AuditRow`]'s `Serialize` doc). Pure and synchronous so it's unit-
/// testable without a socket; [`send_syslog`] is the only caller.
fn format_rfc5424(row: &AuditRow) -> String {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let pid = std::process::id();
    // `unwrap_or_default()` can't actually trigger for this struct (no
    // non-string map keys, no NaN floats) but keeps a serialization
    // regression from panicking the fire-and-forget path — same reasoning
    // as `send_stdout`'s `groups` encoding.
    let body = serde_json::to_string(row).unwrap_or_default();
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // HOSTNAME and STRUCTURED-DATA are RFC 5424 NILVALUE ("-") — the
    // gateway doesn't track its own hostname, and the JSON body already
    // carries every field, so there's nothing structured data would add.
    format!("<{SYSLOG_PRI}>1 {timestamp} - {SYSLOG_APP_NAME} {pid} audit - {body}")
}

/// Best-effort UDP send. Spawns a detached task so DNS resolution and the
/// send itself never delay the caller — a broken or unreachable syslog
/// receiver must not slow down, let alone fail, the agent's request
/// (CLAUDE.md non-negotiable #4 applies to the durable write only; this is
/// the sidecar spec 07 describes). Binds a fresh ephemeral socket per call
/// rather than pooling one in shared state: simplest correct thing, and
/// audit-row volume doesn't warrant the plumbing yet.
fn send_syslog(host: &str, port: u16, row: &AuditRow) {
    let message = format_rfc5424(row);
    let host = host.to_string();
    tokio::spawn(async move {
        let mut addrs = match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => addrs,
            Err(err) => {
                tracing::error!(%err, host, port, "syslog stream sink: DNS resolution failed");
                return;
            }
        };
        let Some(addr) = addrs.next() else {
            tracing::error!(
                host,
                port,
                "syslog stream sink: host resolved to no addresses"
            );
            return;
        };
        // Bind an unspecified local port on the matching family — `send_to`
        // below targets `addr` explicitly, so no `connect()` is needed.
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(err) => {
                tracing::error!(%err, "syslog stream sink: local UDP bind failed");
                return;
            }
        };
        if let Err(err) = socket.send_to(message.as_bytes(), addr).await {
            tracing::error!(%err, host, port, "syslog stream sink: send failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
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

    /// Pure formatting, no socket needed: PRI/version/header shape, and the
    /// MSG body is exactly the row's JSON serialization.
    #[test]
    fn format_rfc5424_has_the_expected_header_and_json_body() {
        let row = sample_row();
        let formatted = format_rfc5424(&row);

        assert!(formatted.starts_with("<134>1 "), "{formatted}");
        // HOSTNAME(-) APP-NAME PROCID MSGID STRUCTURED-DATA(-), then MSG.
        assert!(
            formatted.contains(" - db-mcp-gateway "),
            "missing APP-NAME/nil HOSTNAME: {formatted}"
        );
        assert!(
            formatted.contains(" audit - {"),
            "missing MSGID/nil SD: {formatted}"
        );

        let msg_start = formatted.find('{').expect("MSG body is JSON");
        let body: serde_json::Value =
            serde_json::from_str(&formatted[msg_start..]).expect("MSG body parses as JSON");
        assert_eq!(body["request_id"].as_str(), Some("req-stream-1"));
        assert_eq!(body["tool"].as_str(), Some("run_query"));
        assert_eq!(body["outcome"].as_str(), Some("success"));
    }

    /// End-to-end: `send` with a `Syslog` sink actually puts a datagram on
    /// the wire. Binds a real UDP socket to localhost and receives from it
    /// — spawning is detached (fire-and-forget), so the test polls briefly
    /// rather than assuming the send lands before `send` returns.
    #[tokio::test]
    async fn syslog_sink_delivers_udp_datagram_to_configured_host_port() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral UDP listener");
        let port = listener.local_addr().unwrap().port();

        send(
            &[StreamSinkConfig::Syslog {
                host: "127.0.0.1".to_string(),
                port,
            }],
            &sample_row(),
        );

        let mut buf = [0u8; 4096];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut buf))
            .await
            .expect("received a datagram within 2s — the spawned send should be near-instant on loopback")
            .expect("recv_from succeeds");
        let received = String::from_utf8_lossy(&buf[..n]);
        assert!(received.starts_with("<134>1 "), "{received}");
        assert!(received.contains("req-stream-1"), "{received}");
        assert!(received.contains("run_query"), "{received}");
    }

    /// An unresolvable host must not panic the spawned task — it logs and
    /// returns. Nothing to assert on the wire; this just proves `send`
    /// itself returns immediately regardless (the caller never awaits or
    /// blocks on DNS failure).
    #[test]
    fn syslog_sink_with_bad_host_does_not_block_the_caller() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            send(
                &[StreamSinkConfig::Syslog {
                    host: "this-host-does-not-resolve.invalid".to_string(),
                    port: 514,
                }],
                &sample_row(),
            );
            // `send` already returned above without awaiting the spawned
            // task — the assertion is simply that we got here.
        });
    }
}
