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

/// A configured `stdout` sink emits the streamed event, and the durable
/// state-DB row still lands — the two are additive, not either/or.
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

    let streamed = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(streamed.contains("audit_stream"), "{streamed}");
    assert!(streamed.contains(&request_id.to_string()), "{streamed}");
    assert!(streamed.contains("run_query"), "{streamed}");
    assert!(streamed.contains("SELECT 1"), "{streamed}");

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("durable audit row was written");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.request_id, request_id.to_string());
}

/// No sinks configured (the default) → nothing streamed, only the durable
/// row. Pins the pre-#218 behavior so a future sink addition can't make
/// silence the accidental default.
#[tokio::test]
async fn no_configured_sinks_streams_nothing() {
    let p = pool().await;
    let user = format!("stream-test-noop-{}", Uuid::new_v4().simple());
    let id: Value = json!(1);
    let ctx = RequestContext::default();
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
}
