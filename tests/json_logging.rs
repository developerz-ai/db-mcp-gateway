//! Acceptance for #14: the log lines a real `tools/call` emits, captured
//! through a subscriber built exactly like production's
//! (`src/startup/logging.rs::init_logging`), parse as JSON and carry the
//! documented fields (`request_id`, `user_sub`, `tool`, `db`, `duration_ms`,
//! `outcome`) — on the event itself, since span fields never render.
//!
//! Own test binary: the subscriber is process-global so the gateway's tasks,
//! on any worker thread, write into the capture buffer. Writes an audit row
//! to the real state DB; run under the shared DB lock.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::audit::assert_audit_outcome;
use common::cleanup::delete_audit_calls;
use common::env::state_pool;
use common::gateway::GatewayBuilder;
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

const TOKEN: &str = "dbmcp_svc_7777777777777777777777777777777777777777777777777777777777777777";
const SUB: &str = "service:json-log-bot";
/// A query grant on a server nothing listens on: `run_query` gets past
/// authz and the SQL guard (emitting its pre-dispatch line), then fails to
/// connect — a real dispatch with no target DB.
const YAML: &str = "servers:
  - name: dead
    kind: postgres
    host: 127.0.0.1
    port: 1
    databases:
      - { name: app, role: ro, password: unused }
permissions:
  - group: svc-json-log
    grants:
      - { server: dead, database: app, action: query_read }
service_accounts:
  - name: json-log-bot
    group: svc-json-log
    token: dbmcp_svc_7777777777777777777777777777777777777777777777777777777777777777
";
const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl BufWriter {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("subscriber wrote UTF-8")
    }
}

impl Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Install the production-shaped subscriber once for the whole binary.
fn capture() -> &'static BufWriter {
    static BUF: OnceLock<BufWriter> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = BufWriter::default();
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("info,sqlx::query=warn"))
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_target(true)
            .with_writer(buf.clone())
            .init();
        buf
    })
}

/// Parsed captured lines whose `message` is `message` and whose
/// `request_id` is `request_id`.
fn lines_for(buf: &BufWriter, message: &str, request_id: &str) -> Vec<Value> {
    buf.text()
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|err| panic!("log line is not JSON: {err}\nline: {line}"))
        })
        .filter(|log| log["message"] == message && log["request_id"] == request_id)
        .collect()
}

/// Poll the capture until exactly one matching line exists.
async fn one_line(buf: &BufWriter, message: &str, request_id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let mut found = lines_for(buf, message, request_id);
        match found.len() {
            1 => return found.remove(0),
            0 if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            n => panic!("expected one `{message}` line for {request_id}, got {n}"),
        }
    }
}

fn assert_flat(log: &Value) {
    // No nested `span` / `spans` keys — Alloy parses without a nested stage.
    assert!(log.get("span").is_none(), "nested `span` key: {log}");
    assert!(log.get("spans").is_none(), "nested `spans` key: {log}");
}

#[tokio::test]
async fn real_dispatch_log_lines_match_field_contract() {
    let buf = capture();
    let pool = state_pool().await;
    let gw = GatewayBuilder::new(YAML).spawn(pool.clone()).await;

    let response = reqwest::Client::new()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(TOKEN)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "run_query", "arguments":
                          {"server": "dead", "database": "app", "sql": "SELECT 1"}}}))
        .send()
        .await
        .expect("gateway reachable");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .expect("x-request-id is ASCII")
        .to_owned();
    assert_eq!(response.status(), 200);

    // The chokepoint summary line: the documented contract for every tool.
    let dispatched = one_line(buf, "tool dispatched", &request_id).await;
    for required in [
        "timestamp",
        "level",
        "target",
        "request_id",
        "user_sub",
        "tool",
        "db",
        "duration_ms",
        "outcome",
    ] {
        assert!(
            dispatched.get(required).is_some(),
            "missing `{required}`: {dispatched}"
        );
    }
    assert_eq!(dispatched["level"], "INFO");
    assert_eq!(dispatched["user_sub"], SUB);
    assert_eq!(dispatched["tool"], "run_query");
    assert_eq!(dispatched["db"], "app");
    assert!(dispatched["duration_ms"].is_u64(), "{dispatched}");
    assert_flat(&dispatched);

    // The log and the audit row must tell the same story.
    let outcome = dispatched["outcome"].as_str().expect("outcome string");
    assert_ne!(outcome, "success", "nothing listens on the target");
    assert_audit_outcome(
        &pool,
        SUB,
        "run_query",
        outcome,
        "run_query to a dead server",
    )
    .await;

    // `run_query`'s pre-dispatch line correlates through its own request_id.
    let pre = one_line(buf, "tool.run_query.dispatch", &request_id).await;
    uuid::Uuid::parse_str(&request_id).expect("request_id is a UUID");
    assert_eq!(pre["db"], "app");
    assert_flat(&pre);

    // Credentials never reach the log stream (MUST #1).
    assert!(
        !buf.text().contains(TOKEN),
        "bearer leaked into the log stream"
    );

    delete_audit_calls(&pool, SUB).await;
}

/// Guard against future drift: if a dev adds a log site that interpolates a
/// likely-secret value, this test surfaces it. Heuristic — `Password::Literal`'s
/// hand-rolled Debug prints `Password::Literal(<redacted>)` exactly, so a
/// successful redaction round-trip should still be safe to log.
#[test]
fn redacted_debug_does_not_leak_password() {
    use db_mcp_gateway::config::Password;
    let password = Password::Literal("super-secret-value".into());
    let rendered = format!("{password:?}");
    assert!(!rendered.contains("super-secret-value"));
    assert!(rendered.contains("<redacted>"));
}
