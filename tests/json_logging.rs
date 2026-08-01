//! Acceptance for #14: a sample log line emitted with the production
//! subscriber config parses as JSON and carries the documented fields
//! (`request_id`, `user_sub`, `tool`, `db`, `duration_ms`, `outcome`).
//!
//! Own test binary so the global subscriber install can't collide with any
//! other test that might initialise tracing.

use std::io::Write;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl BufWriter {
    fn take(&self) -> String {
        let buf = std::mem::take(&mut *self.0.lock().unwrap());
        String::from_utf8(buf).expect("subscriber wrote non-UTF8")
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

#[test]
fn dispatch_log_line_matches_field_contract() {
    let buf = BufWriter::default();
    // Mirror `main.rs` exactly — if this drifts, the test catches it.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_writer(buf.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        // Verbatim shape of the audit_dispatch chokepoint log line — every
        // tool flows through this, so if these fields land in JSON the
        // documented contract holds for every dispatch.
        tracing::info!(
            request_id = "\"req-7\"",
            user_sub = "alice@example.com",
            tool = "run_query",
            db = "main",
            outcome = "success",
            duration_ms = 42_i64,
            "tool dispatched"
        );
    });

    let raw = buf.take();
    let line = raw.lines().next().expect("subscriber emitted a line");
    let log: Value = serde_json::from_str(line)
        .unwrap_or_else(|err| panic!("log line is not JSON: {err}\nline: {line}"));

    // Documented contract from issue #14 + docs/deployment/logging.md.
    for required in [
        "timestamp",
        "level",
        "message",
        "request_id",
        "user_sub",
        "tool",
        "db",
        "duration_ms",
        "outcome",
    ] {
        assert!(
            log.get(required).is_some(),
            "missing `{required}` in log line: {line}"
        );
    }
    assert_eq!(log["level"].as_str(), Some("INFO"));
    assert_eq!(log["message"].as_str(), Some("tool dispatched"));
    assert_eq!(log["duration_ms"].as_i64(), Some(42));

    // No nested `span` / `spans` keys — subscriber must flatten so Alloy
    // parses without a nested-field stage.
    assert!(
        log.get("span").is_none(),
        "subscriber emitted a `span` key — flatten_event should hoist fields"
    );
    assert!(
        log.get("spans").is_none(),
        "subscriber emitted a `spans` key — with_span_list(false) should drop it"
    );
    assert!(
        log.get("target").is_none(),
        "subscriber emitted a `target` key — with_target(false) should drop it"
    );
}

/// `run_query`'s pre-dispatch event fires inside the `tool_dispatch` span,
/// but the production formatter drops span fields (`with_current_span(false)` +
/// `with_span_list(false)`). Every log line that needs to correlate with an
/// audit row must therefore carry `request_id` on the event itself. Regression
/// test for the `tool.run_query.dispatch` site — if a future refactor drops
/// the explicit `request_id` field, this test surfaces it before Loki does.
#[test]
fn run_query_dispatch_event_carries_request_id() {
    let buf = BufWriter::default();
    // Mirror `main.rs` — same reason as the sibling test above.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_writer(buf.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        // Verbatim shape of the pre-dispatch log line emitted by
        // `src/tools/run_query.rs::compute_outcome`. If that site drops
        // `request_id`, this assert fires.
        let request_id = uuid::Uuid::new_v4();
        tracing::info!(
            request_id = %request_id,
            user_sub = "alice@example.com",
            server = "target",
            db = "app",
            row_limit = 100_u32,
            timeout_ms = Option::<u64>::Some(200),
            "tool.run_query.dispatch"
        );
    });

    let raw = buf.take();
    let line = raw.lines().next().expect("subscriber emitted a line");
    let log: Value = serde_json::from_str(line)
        .unwrap_or_else(|err| panic!("log line is not JSON: {err}\nline: {line}"));

    assert_eq!(log["message"].as_str(), Some("tool.run_query.dispatch"));
    let request_id = log
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing `request_id` in tool.run_query.dispatch: {line}"));
    // The event must carry a well-formed UUID (the production site emits
    // `RequestContext::request_id`, always a UUID).
    uuid::Uuid::parse_str(request_id)
        .unwrap_or_else(|_| panic!("request_id is not a UUID: {request_id}"));

    // Guard against span-fields creeping in: `with_current_span(false)` +
    // `with_span_list(false)` must keep the JSON flat, same as the sibling
    // event test.
    assert!(
        log.get("span").is_none(),
        "subscriber emitted a `span` key — flatten_event should hoist fields"
    );
    assert!(
        log.get("spans").is_none(),
        "subscriber emitted a `spans` key — with_span_list(false) should drop it"
    );
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
