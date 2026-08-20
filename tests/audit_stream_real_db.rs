//! Stream-sink fan-out for `audit_dispatch` (#218): a configured `stdout`
//! sink emits a `target: "audit_stream"` tracing event carrying the row's
//! fields, in addition to — never instead of — the durable `audit_calls`
//! write. No sink configured is a no-op, the pre-#218 default.
//!
//! Exercises the production code path: real `audit_dispatch` call against a
//! real state DB, tracing output captured for the call's duration.

use std::sync::{Arc, Mutex};

use db_mcp_gateway::audit;
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::config::StreamSinkConfig;
use db_mcp_gateway::state;
use db_mcp_gateway::tools::audit_dispatch::{
    AuditHeader, RequestContext, audit_dispatch, success_outcome,
};
use serde_json::{Value, json};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn pool() -> sqlx::PgPool {
    state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "stream-test@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
    }
}

/// Reruns of the real-DB tests must not leave rows behind — each test uses a
/// per-run `user_sub`, but silent accumulation still bloats `audit_calls`
/// over time and would break the `latest_for_user_tool` invariant if a `sub`
/// is ever reused.
async fn cleanup(pool: &sqlx::PgPool, user_sub: &str) {
    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(user_sub)
        .execute(pool)
        .await
        .expect("cleanup delete succeeds");
}

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

/// Writer that fails every write. Models the "sink outage" case — CLAUDE.md
/// non-negotiable: a stream sink failure must never fail an agent's request
/// or block the durable write. If tracing swallows the error at the writer
/// boundary (it does), `audit_dispatch` must return `Ok` and the durable row
/// must land regardless.
#[derive(Clone, Default)]
struct FailingWriter;

impl std::io::Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("simulated sink outage"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("simulated sink outage"))
    }
}

impl<'a> MakeWriter<'a> for FailingWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A configured `stdout` sink emits the streamed event, and the durable
/// state-DB row still lands — the two are additive, not either/or. Uses the
/// JSON formatter so we assert on the structured event contract (target +
/// field names + AuditRow data) instead of substring-matching against the
/// human-readable line, which any unrelated tracing line could satisfy.
#[tokio::test]
async fn configured_stdout_sink_streams_and_still_writes_the_durable_row() {
    let p = pool().await;
    let user = format!("stream-test-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let id: Value = json!(1);
    let ctx = RequestContext {
        request_id,
        ..RequestContext::default()
    };
    let identity = identity(&user);
    let header = AuditHeader {
        tool: "run_query",
        server: Some("prod"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    };
    let outcome = success_outcome(id.clone(), "{}".to_string(), Some(4), Some(1), Some(false));

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
    // `#[tokio::test]` defaults to the current-thread flavor, so the whole
    // test body — including everything `audit_dispatch` awaits or spawns —
    // stays on this one OS thread, and `set_default`'s thread-local guard
    // covers it. Dropped (and the capture ends) when it goes out of scope
    // at the end of the test.
    let _guard = tracing::subscriber::set_default(subscriber);

    let _response = audit_dispatch(
        id,
        &identity,
        Some(&p),
        &ctx,
        header,
        &[StreamSinkConfig::Stdout],
        std::future::ready(outcome),
    )
    .await;

    // Locate the `audit_stream` event among the multiple log lines
    // `audit_dispatch` emits (the "tool dispatched" summary line rides the
    // same subscriber). Filtering by target is why we assert the structured
    // contract — substring matches could latch onto unrelated events.
    let raw = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let event = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["target"].as_str() == Some("audit_stream"))
        .unwrap_or_else(|| panic!("no audit_stream event in output:\n{raw}"));

    assert_eq!(event["message"].as_str(), Some("audit row streamed"));
    assert_eq!(event["request_id"].as_str(), Some(&*request_id.to_string()));
    assert_eq!(event["user_sub"].as_str(), Some(&*user));
    assert_eq!(event["tool"].as_str(), Some("run_query"));
    assert_eq!(event["server"].as_str(), Some("prod"));
    assert_eq!(event["database"].as_str(), Some("app"));
    assert_eq!(event["sql"].as_str(), Some("SELECT 1"));
    assert_eq!(event["outcome"].as_str(), Some("success"));
    assert_eq!(event["db_type"].as_str(), Some("postgres"));
    // Full field mirror: `audit_id` correlates the streamed event to the
    // durable row a SIEM consumer would join against.
    let audit_id_str = event["audit_id"]
        .as_str()
        .unwrap_or_else(|| panic!("event missing audit_id: {event}"));
    Uuid::parse_str(audit_id_str).expect("audit_id is a UUID");

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("durable audit row was written");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.request_id, request_id.to_string());
    assert_eq!(row.id.to_string(), audit_id_str);

    cleanup(&p, &user).await;
}

/// Sink outage is fire-and-forget: a stdout writer that fails on every write
/// must NOT propagate to the caller. `audit_dispatch` returns normally and
/// the durable audit row lands unchanged. Regression guard for CLAUDE.md
/// non-negotiable #4 — audit write commits (and its response goes out) even
/// when a stream sink is broken.
#[tokio::test]
async fn failing_stdout_sink_does_not_block_response_or_durable_write() {
    let p = pool().await;
    let user = format!("stream-test-fail-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let id: Value = json!(1);
    let ctx = RequestContext {
        request_id,
        ..RequestContext::default()
    };
    let identity = identity(&user);
    let header = AuditHeader {
        tool: "run_query",
        server: Some("prod"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    };
    let outcome = success_outcome(id.clone(), "{}".to_string(), Some(4), Some(1), Some(false));

    let subscriber = tracing_subscriber::fmt()
        .with_writer(FailingWriter)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let response = audit_dispatch(
        id,
        &identity,
        Some(&p),
        &ctx,
        header,
        &[StreamSinkConfig::Stdout],
        std::future::ready(outcome),
    )
    .await;
    // Serialisation succeeds and the response is a JSON-RPC result, not an
    // error — the sink failure never surfaced.
    let body = serde_json::to_value(&response).expect("response serialises");
    assert!(
        body.get("result").is_some(),
        "expected JSON-RPC result, got: {body}"
    );

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("durable audit row was written despite sink failure");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.request_id, request_id.to_string());

    cleanup(&p, &user).await;
}

/// No sinks configured (the default) → nothing streamed, only the durable
/// row. Pins the pre-#218 behavior so a future sink addition can't make
/// silence the accidental default. Also asserts the durable row lands — an
/// empty sink list must exercise the primary `audit::log` path, not
/// short-circuit past it.
#[tokio::test]
async fn no_configured_sinks_streams_nothing() {
    let p = pool().await;
    let user = format!("stream-test-noop-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let id: Value = json!(1);
    let ctx = RequestContext {
        request_id,
        ..RequestContext::default()
    };
    let identity = identity(&user);
    let header = AuditHeader {
        tool: "list_servers",
        server: None,
        database: None,
        sql: None,
        reason: None,
        db_type: None,
    };
    let outcome = success_outcome(id.clone(), "[]".to_string(), Some(1), None, None);

    let buf = BufWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let _response = audit_dispatch(
        id,
        &identity,
        Some(&p),
        &ctx,
        header,
        &[],
        std::future::ready(outcome),
    )
    .await;

    let streamed = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(!streamed.contains("audit_stream"), "{streamed}");

    // Durable write still lands. The empty-sink path must NOT skip
    // `audit::log` — spec 07 makes the state-DB write mandatory whether or
    // not stream sinks are configured.
    let row = audit::latest_for_user_tool(&p, &user, "list_servers")
        .await
        .expect("audit query runs")
        .expect("durable audit row was written for empty-sink dispatch");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.request_id, request_id.to_string());

    cleanup(&p, &user).await;
}

/// The same wiring proof as the `stdout` test above, for `syslog`: a
/// configured sink delivers a real UDP datagram AND the durable row lands.
/// The RFC 5424 formatting itself is unit-tested in `audit::stream`; this
/// test is only about `audit_dispatch` actually reaching the sink.
#[tokio::test]
async fn configured_syslog_sink_delivers_udp_and_still_writes_the_durable_row() {
    let p = pool().await;
    let user = format!("stream-test-syslog-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let id: Value = json!(1);
    let ctx = RequestContext {
        request_id,
        ..RequestContext::default()
    };
    let identity = identity(&user);
    let header = AuditHeader {
        tool: "run_query",
        server: Some("prod"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    };
    let outcome = success_outcome(id.clone(), "{}".to_string(), Some(4), Some(1), Some(false));

    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral UDP listener");
    let port = listener.local_addr().unwrap().port();

    let _response = audit_dispatch(
        id,
        &identity,
        Some(&p),
        &ctx,
        header,
        &[StreamSinkConfig::Syslog {
            host: "127.0.0.1".to_string(),
            port,
        }],
        std::future::ready(outcome),
    )
    .await;

    let mut buf = [0u8; 4096];
    let (n, _from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        listener.recv_from(&mut buf),
    )
    .await
    .expect("received a syslog datagram within 2s")
    .expect("recv_from succeeds");
    let received = String::from_utf8_lossy(&buf[..n]);
    assert!(received.starts_with("<134>1 "), "{received}");
    assert!(received.contains(&request_id.to_string()), "{received}");
    assert!(received.contains("run_query"), "{received}");

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("durable audit row was written");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.request_id, request_id.to_string());

    cleanup(&p, &user).await;
}
