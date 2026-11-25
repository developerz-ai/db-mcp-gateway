//! The size cap: what an oversized row keeps, and how a cut is marked.

use proptest::prelude::*;
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;
use crate::audit::OutcomeCode;

fn row() -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: "req-cut-1".into(),
        user_sub: "user-1".into(),
        user_email: "u@example.com".into(),
        groups: vec!["engineers".into()],
        tool: "run_query".into(),
        server: Some("prod".into()),
        database: Some("app".into()),
        sql: Some("SELECT 1".into()),
        reason: None,
        outcome: OutcomeCode::Timeout,
        elapsed_ms: Some(4),
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".into()),
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
        params: None,
    }
}

fn body(message: &str) -> Value {
    assert!(message.len() <= MAX_MESSAGE_BYTES, "{}", message.len());
    serde_json::from_str(&message[message.find('{').expect("a body")..]).expect("body is JSON")
}

/// `cut` is a prefix of `whole` plus the marker, at least `floor` bytes long.
fn assert_cut(cut: &Value, whole: &str, floor: usize) {
    let cut = cut.as_str().expect("a cut field is a string");
    let kept = cut.strip_suffix(TRUNCATION_MARKER).expect("marked");
    assert!(whole.starts_with(kept), "{kept}");
    assert!(kept.len() >= floor, "kept {} bytes", kept.len());
}

/// A long error message keeps every byte that fits, and costs no other
/// field its text.
#[test]
fn a_long_error_message_is_cut_to_fit_with_the_marker() {
    let mut row = row();
    row.reason = Some("incident-42".into());
    let error = "e".repeat(20_000);
    row.error_message = Some(error.clone());

    let message = message(&row);
    let body = body(&message);

    assert_cut(&body["error_message"], &error, 6_000);
    assert_eq!(body["sql"], "SELECT 1");
    assert_eq!(body["reason"], "incident-42");
}

/// Neither the statement nor the error can absorb the excess alone: both are
/// cut, and the row keeps its identity fields.
#[test]
fn a_long_error_beside_a_long_statement_leaves_both_readable() {
    let mut row = row();
    let (sql, error) = ("s".repeat(64 * 1024), "e".repeat(20_000));
    row.sql = Some(sql.clone());
    row.error_message = Some(error.clone());

    let body = body(&message(&row));

    assert_cut(&body["sql"], &sql, 500);
    assert_cut(&body["error_message"], &error, 500);
    assert_eq!(body["user_sub"], "user-1");
}

/// The caps of `sql` and `params` allow both to be 64 KiB at once.
#[test]
fn a_long_statement_with_long_params_leaves_both_readable() {
    let mut row = row();
    let sql = "s".repeat(64 * 1024);
    let params = json!(["\"q\"".repeat(10_000)]);
    row.sql = Some(sql.clone());
    row.params = Some(params.clone());

    let body = body(&message(&row));

    assert_cut(&body["sql"], &sql, 500);
    assert_cut(&body["params"], &params.to_string(), 200);
}

/// `audit_calls` already stores over-cap params as a string; a further cut
/// shortens that text, not a second encoding of it.
#[test]
fn params_stored_as_a_cut_string_are_cut_as_that_string() {
    let mut row = row();
    let stored = r#"["a","#.repeat(4_000);
    row.params = Some(Value::String(stored.clone()));

    assert_cut(&body(&message(&row))["params"], &stored, 1_000);
}

/// Groups alone pass the cap: the identity is sent, with the error message's
/// prefix and its marker.
#[test]
fn the_last_resort_keeps_a_marked_error_message() {
    let mut row = row();
    row.groups = vec!["g".repeat(9_000)];
    let error = "\u{1}".repeat(20_000);
    row.error_message = Some(error.clone());

    let body = body(&message(&row));

    assert_eq!(body["message_truncated"], true);
    assert_eq!(body["request_id"], "req-cut-1");
    assert_eq!(body["outcome"], "timeout");
    assert_cut(&body["error_message"], &error, 50);

    row.error_message = Some("short".into());
    let whole = super::message(&row);
    assert_eq!(self::body(&whole)["error_message"], "short");
    row.error_message = None;
    let none = super::message(&row);
    assert_eq!(self::body(&none)["error_message"], Value::Null);
}

fn text() -> impl Strategy<Value = Option<String>> {
    // Sizes around the floor and the cap; characters of every escape length.
    let piece = prop_oneof![Just("a"), Just("\""), Just("\u{1}"), Just("é"), Just("\n")];
    let size = prop_oneof![0..20_usize, 480..560_usize, 0..12_000_usize];
    proptest::option::of((piece, size).prop_map(|(piece, n)| piece.repeat(n)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Whatever the row: one message within the cap, its body an object, and
    /// each text field whole or a marked prefix.
    #[test]
    fn every_message_fits_and_every_cut_is_marked(
        sql in text(), params in text(), reason in text(), error in text(),
        agent in text(), actor in text(), run in text(), groups in 0..10_000_usize,
    ) {
        let mut row = row();
        row.groups = vec!["g".repeat(groups)];
        row.sql = sql;
        row.params = params.map(|text| json!([text]));
        row.reason = reason;
        row.error_message = error;
        row.agent_client = agent;
        row.upstream_actor = actor;
        row.upstream_run_id = run;

        let body = body(&message(&row));
        let whole = serde_json::to_value(&row).unwrap();
        for (field, sent) in body.as_object().unwrap() {
            if field == "message_truncated" || *sent == whole[field] {
                continue;
            }
            let full = match &whole[field] {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            assert_cut(sent, &full, 0);
        }
    }
}
