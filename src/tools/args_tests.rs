//! Unit tests for the argument edge.

use serde::Deserialize;
use serde_json::json;

use super::*;

#[test]
fn nul_is_refused_in_every_string_argument() {
    for key in ["server", "sql", "reason", "since", "anything"] {
        let err = check_arguments(&json!({ key: "a\u{0}b" })).unwrap_err();
        assert!(err.contains(key), "{err}");
        assert!(!err.contains('\u{0}'));
    }
}

#[test]
fn free_text_keeps_line_breaks_identifiers_do_not() {
    assert!(check_arguments(&json!({ "sql": "select 1\n\tfrom t\r\n" })).is_ok());
    assert!(check_arguments(&json!({ "reason": "line one\nline two" })).is_ok());
    assert!(check_arguments(&json!({ "server": "prod\n" })).is_err());
    assert!(check_arguments(&json!({ "reason": "bell\u{7}" })).is_err());
    assert!(check_arguments(&json!({ "reason": "c1\u{85}" })).is_err());
}

#[test]
fn lengths_are_bounded_per_kind_without_echoing_the_value() {
    let long_name = "s".repeat(IDENTIFIER_MAX_BYTES + 1);
    let err = check_arguments(&json!({ "server": long_name })).unwrap_err();
    assert!(err.contains("`server`") && err.len() < 64, "{err}");
    let name = "s".repeat(IDENTIFIER_MAX_BYTES);
    assert!(check_arguments(&json!({ "server": name })).is_ok());

    let reason = "r".repeat(REASON_MAX_BYTES + 1);
    assert!(check_arguments(&json!({ "reason": reason })).is_err());
    let sql = "x".repeat(SQL_MAX_BYTES + 1);
    assert!(check_arguments(&json!({ "sql": sql })).is_err());
    let sql = "x".repeat(SQL_MAX_BYTES);
    assert!(check_arguments(&json!({ "sql": sql })).is_ok());
}

#[test]
fn keys_and_nested_values_are_checked_too() {
    assert!(check_arguments(&json!({ "a\u{0}": 1 })).is_err());
    assert!(check_arguments(&json!({ "k".repeat(65): 1 })).is_err());
    assert!(check_arguments(&json!({ "list": ["ok", "bad\u{0}"] })).is_err());
    assert!(check_arguments(&json!({ "obj": { "reason": "\u{0}" } })).is_err());
    assert!(check_arguments(&json!("not an object")).is_err());
    assert!(check_arguments(&Value::Null).is_ok());
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    #[allow(dead_code)]
    sql: String,
    #[serde(default)]
    #[allow(dead_code)]
    limit: Option<u32>,
}

#[test]
fn parse_errors_name_the_field() {
    let err = parse_arguments::<Sample>(Some(json!({ "sql": "x", "bogus": 1 }))).unwrap_err();
    assert!(err.contains("bogus"), "{err}");
    let err = parse_arguments::<Sample>(Some(json!({ "sql": "x", "limit": -1 }))).unwrap_err();
    assert!(err.contains("-1") && err.contains("u32"), "{err}");
    let err = parse_arguments::<Sample>(Some(json!({}))).unwrap_err();
    assert!(err.contains("`sql`"), "{err}");
    assert!(parse_arguments::<Sample>(None).is_err());
}

#[test]
fn parse_errors_are_capped() {
    let long = "x".repeat(10_000);
    let err = parse_arguments::<Sample>(Some(json!({ "sql": "x", "limit": long }))).unwrap_err();
    assert!(err.len() <= PARSE_ERROR_MAX_BYTES, "{}", err.len());
}
