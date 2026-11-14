//! Result shapes as shipped: columns per shape, the row/byte budget, and
//! replies that do not fit their documented shape.

use redis::Value as Reply;
use serde_json::json;

use super::*;
use crate::exec::MAX_RESULT_BYTES;

fn bulk(s: &str) -> Reply {
    Reply::BulkString(s.as_bytes().to_vec())
}

fn shaped(shape: Shape, reply: Reply, row_limit: u32) -> Shaped {
    shape_reply(shape, reply, row_limit).expect("reply fits its shape")
}

#[test]
fn a_scalar_is_one_value_row() {
    let out = shaped(Shape::Value, bulk("hello"), 10);
    assert_eq!(out.columns, ["value"]);
    assert_eq!(out.rows, vec![vec![json!("hello")]]);
    assert!(!out.truncated);
    // A missing key is Redis' own nil, one row.
    let out = shaped(Shape::Value, Reply::Nil, 10);
    assert_eq!(out.rows, vec![vec![Value::Null]]);
    let out = shaped(Shape::Value, Reply::Int(3), 10);
    assert_eq!(out.rows, vec![vec![json!(3)]]);
}

#[test]
fn an_array_is_one_row_per_element() {
    let reply = Reply::Array(vec![bulk("a"), Reply::Nil, Reply::Array(vec![bulk("x")])]);
    let out = shaped(Shape::Value, reply, 10);
    assert_eq!(out.columns, ["value"]);
    assert_eq!(
        out.rows,
        vec![vec![json!("a")], vec![Value::Null], vec![json!(["x"])]]
    );
}

#[test]
fn hash_pairs_come_from_a_flat_array_or_a_map() {
    let flat = Reply::Array(vec![bulk("name"), bulk("ada"), bulk("age"), bulk("36")]);
    let out = shaped(Shape::FieldValue, flat, 10);
    assert_eq!(out.columns, ["field", "value"]);
    assert_eq!(
        out.rows,
        vec![
            vec![json!("name"), json!("ada")],
            vec![json!("age"), json!("36")]
        ]
    );

    let map = Reply::Map(vec![(bulk("name"), bulk("ada"))]);
    let out = shaped(Shape::Value, map, 10);
    assert_eq!(out.columns, ["field", "value"]);
    assert_eq!(out.rows, vec![vec![json!("name"), json!("ada")]]);
}

#[test]
fn zset_scores_pair_with_members_in_resp2_and_resp3_form() {
    let resp2 = Reply::Array(vec![bulk("a"), bulk("1"), bulk("b"), bulk("2.5")]);
    let out = shaped(Shape::MemberScore, resp2, 10);
    assert_eq!(out.columns, ["member", "score"]);
    assert_eq!(out.rows[1], vec![json!("b"), json!("2.5")]);

    let resp3 = Reply::Array(vec![Reply::Array(vec![bulk("a"), Reply::Double(1.0)])]);
    let out = shaped(Shape::MemberScore, resp3, 10);
    assert_eq!(out.rows, vec![vec![json!("a"), json!(1.0)]]);
}

#[test]
fn a_missing_key_is_zero_pair_rows() {
    let out = shaped(Shape::FieldValue, Reply::Array(vec![]), 10);
    assert!(out.rows.is_empty());
    let out = shaped(Shape::FieldValue, Reply::Nil, 10);
    assert!(out.rows.is_empty());
}

#[test]
fn an_odd_pair_list_is_a_decode_error_not_a_padded_null() {
    let odd = Reply::Array(vec![bulk("field-without-value")]);
    assert!(matches!(
        shape_reply(Shape::FieldValue, odd, 10),
        Err(ExecError::Decode)
    ));
    assert!(matches!(
        shape_reply(Shape::Scan(ScanItem::Key), bulk("x"), 10),
        Err(ExecError::Decode)
    ));
}

#[test]
fn scan_rows_lead_with_the_next_cursor() {
    let page = Reply::Array(vec![bulk("17"), Reply::Array(vec![bulk("k1"), bulk("k2")])]);
    let out = shaped(Shape::Scan(ScanItem::Key), page, 10);
    assert_eq!(out.columns, ["next_cursor", "key"]);
    assert_eq!(
        out.rows,
        vec![
            vec![json!("17"), json!("k1")],
            vec![json!("17"), json!("k2")]
        ]
    );

    let page = Reply::Array(vec![bulk("0"), Reply::Array(vec![bulk("f"), bulk("v")])]);
    let out = shaped(Shape::Scan(ScanItem::FieldValue), page, 10);
    assert_eq!(out.columns, ["next_cursor", "field", "value"]);
    assert_eq!(out.rows, vec![vec![json!("0"), json!("f"), json!("v")]]);

    let page = Reply::Array(vec![bulk("0"), Reply::Array(vec![bulk("m"), bulk("1")])]);
    let out = shaped(Shape::Scan(ScanItem::MemberScore), page, 10);
    assert_eq!(out.columns, ["next_cursor", "member", "score"]);
}

/// SCAN may answer an empty page mid-iteration; the cursor must survive it.
#[test]
fn an_empty_scan_page_still_carries_the_cursor() {
    let page = Reply::Array(vec![bulk("42"), Reply::Array(vec![])]);
    let out = shaped(Shape::Scan(ScanItem::Member), page, 10);
    assert_eq!(out.columns, ["next_cursor", "member"]);
    assert_eq!(out.rows, vec![vec![json!("42"), Value::Null]]);
    let page = Reply::Array(vec![bulk("42"), Reply::Array(vec![])]);
    let out = shaped(Shape::Scan(ScanItem::FieldValue), page, 10);
    assert_eq!(out.rows, vec![vec![json!("42"), Value::Null, Value::Null]]);
}

#[test]
fn stream_entries_carry_their_fields_as_an_object() {
    let entry = Reply::Array(vec![
        bulk("1-0"),
        Reply::Array(vec![
            bulk("event"),
            bulk("login"),
            bulk("user"),
            bulk("ada"),
        ]),
    ]);
    let out = shaped(Shape::Stream, Reply::Array(vec![entry]), 10);
    assert_eq!(out.columns, ["id", "fields"]);
    assert_eq!(
        out.rows,
        vec![vec![json!("1-0"), json!({"event": "login", "user": "ada"})]]
    );
}

#[test]
fn the_row_limit_truncates_and_flags_it() {
    let reply = Reply::Array((0..5).map(Reply::Int).collect());
    let out = shaped(Shape::Value, reply, 3);
    assert_eq!(out.rows.len(), 3);
    assert!(out.truncated);
    // Exactly at the limit is not truncated.
    let reply = Reply::Array((0..3).map(Reply::Int).collect());
    assert!(!shaped(Shape::Value, reply, 3).truncated);
    // A zero cap returns nothing, and says so.
    let out = shaped(Shape::Value, bulk("x"), 0);
    assert!(out.rows.is_empty());
    assert!(out.truncated);
}

#[test]
fn the_byte_budget_truncates_an_oversized_value() {
    let huge = "x".repeat(MAX_RESULT_BYTES + 1);
    let out = shaped(
        Shape::Value,
        Reply::Array(vec![bulk("small"), bulk(&huge)]),
        10,
    );
    assert_eq!(out.rows, vec![vec![json!("small")]]);
    assert!(out.truncated);
}
