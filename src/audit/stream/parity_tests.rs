//! Field parity: every `AuditRow` field reaches every sink. The field list is
//! taken from `AuditRow`'s own serialization, so a column added to the row
//! fails here until each sink carries it (or the exclusion below names why
//! it does not).

use std::sync::{Arc, Mutex};

use serde_json::Value;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

use super::syslog::format_rfc5424;
use super::*;
use crate::audit::OutcomeCode;

/// Sink spellings that differ from the `AuditRow` field name. stdout says
/// `audit_id` because `id` is ambiguous beside the gateway's other log
/// fields.
const STDOUT_RENAMES: &[(&str, &str)] = &[("id", "audit_id")];

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

/// Every optional field set, so a sink that leaves `None` out still has to
/// show the field.
fn full_row() -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: "req-parity".into(),
        user_sub: "service:etl".into(),
        user_email: "etl@service.invalid".into(),
        groups: vec!["etl".into()],
        tool: "run_query".into(),
        server: Some("prod".into()),
        database: Some("app".into()),
        sql: Some("UPDATE t SET x = 1".into()),
        reason: Some("backfill".into()),
        outcome: OutcomeCode::Success,
        elapsed_ms: Some(9),
        row_count: Some(0),
        truncated: Some(false),
        error_message: Some("none".into()),
        agent_client: Some("agent/1".into()),
        ip: Some("10.0.0.9".into()),
        db_type: Some("postgres".into()),
        upstream_actor: Some("alice@example.com".into()),
        upstream_run_id: Some("run-7".into()),
        rows_affected: Some(3),
        sql_truncated: true,
    }
}

fn row_fields(row: &AuditRow) -> Vec<String> {
    let Value::Object(fields) = serde_json::to_value(row).unwrap() else {
        panic!("AuditRow serializes as an object");
    };
    fields.keys().cloned().collect()
}

fn stdout_event(row: &AuditRow) -> Value {
    let buf = BufWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .json()
        .flatten_event(true)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        StreamSinks::from_config(&[StreamSinkConfig::Stdout])
            .expect("stdout sink")
            .send(row, &DetachedTasks::new());
    });
    let raw = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    serde_json::from_str(raw.lines().next().expect("one event")).unwrap()
}

#[test]
fn stdout_carries_every_audit_row_field() {
    let row = full_row();
    let event = stdout_event(&row);
    for field in row_fields(&row) {
        let key = STDOUT_RENAMES
            .iter()
            .find(|(name, _)| *name == field)
            .map_or(field.as_str(), |(_, renamed)| renamed);
        assert!(
            event.get(key).is_some(),
            "stdout event lacks `{key}` (AuditRow::{field}): {event}"
        );
    }
    assert_eq!(event["upstream_actor"], "alice@example.com");
    assert_eq!(event["upstream_run_id"], "run-7");
    assert_eq!(event["rows_affected"], 3);
    assert_eq!(event["sql_truncated"], true);
}

/// A read has no `rows_affected`; stdout leaves the field out rather than
/// reporting a write count of 0.
#[test]
fn stdout_omits_rows_affected_for_a_read() {
    let mut row = full_row();
    row.rows_affected = None;
    assert!(stdout_event(&row).get("rows_affected").is_none());
}

#[test]
fn syslog_body_carries_every_audit_row_field() {
    let row = full_row();
    let message = format_rfc5424(&row);
    let body: Value = serde_json::from_str(&message[message.find('{').unwrap()..]).unwrap();
    for field in row_fields(&row) {
        assert!(body.get(&field).is_some(), "syslog body lacks `{field}`");
    }
}
