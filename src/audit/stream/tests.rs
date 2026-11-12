//! Sink behaviour without a state DB: stdout field contract, RFC 5424 shape,
//! UDP delivery on loopback.

use super::syslog::format_rfc5424;
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
        .expect(
            "received a datagram within 2s — the spawned send should be near-instant on loopback",
        )
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
