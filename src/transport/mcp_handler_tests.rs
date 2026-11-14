use serde_json::{Value, json};

use super::*;
use crate::mcp::jsonrpc::{INVALID_REQUEST, PARSE_ERROR};

fn parse_err(body: &str) -> Value {
    serde_json::to_value(parse(body.as_bytes()).expect_err("must be rejected")).unwrap()
}

fn id_of(body: Value) -> RequestId {
    serde_json::from_value::<Request>(body).unwrap().id
}

#[test]
fn malformed_json_is_a_parse_error() {
    let value = parse_err("{not json");
    assert_eq!(value["error"]["code"], PARSE_ERROR);
    assert_eq!(value["id"], Value::Null);
}

#[test]
fn batch_arrays_are_refused_with_a_clear_message() {
    let value = parse_err(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
    assert_eq!(value["error"]["code"], INVALID_REQUEST);
    assert_eq!(
        value["error"]["message"],
        "batch requests are not supported"
    );
}

#[test]
fn valid_json_that_is_not_a_request_is_invalid_request() {
    for body in ["42", r#""ping""#, "null", "{}"] {
        let value = parse_err(body);
        assert_eq!(value["error"]["code"], INVALID_REQUEST, "{body}");
        assert_eq!(value["id"], Value::Null, "{body}");
    }
}

#[test]
fn invalid_request_echoes_a_recoverable_id() {
    // No `method`, wrong `jsonrpc`: the id is still readable, so echo it.
    for body in [
        r#"{"jsonrpc":"2.0","id":5}"#,
        r#"{"jsonrpc":"1.0","id":5,"method":"ping"}"#,
    ] {
        let value = parse_err(body);
        assert_eq!(value["error"]["code"], INVALID_REQUEST, "{body}");
        assert_eq!(value["id"], 5, "{body}");
    }
}

#[test]
fn absent_id_is_a_notification() {
    let id = id_of(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    assert!(matches!(checked_id(&id), Ok(None)));
}

/// `"id": null` is neither a valid request id (MCP forbids null) nor a
/// notification (only an omitted id qualifies).
#[test]
fn explicit_null_id_is_invalid_request_not_a_notification() {
    let id = id_of(json!({"jsonrpc": "2.0", "id": null, "method": "initialize"}));
    let value = serde_json::to_value(checked_id(&id).expect_err("null id")).unwrap();
    assert_eq!(value["error"]["code"], INVALID_REQUEST);
    assert_eq!(value["id"], Value::Null);
}

/// MCP `RequestId` is `string | number`; anything else is rejected before
/// method work, echoing the original id so the caller can correlate.
#[test]
fn unsupported_id_types_are_invalid_request() {
    for raw in [
        json!(true),
        json!([1, 2]),
        json!({"nested": true}),
        json!(1.5),
    ] {
        let id = id_of(json!({"jsonrpc": "2.0", "id": raw, "method": "initialize"}));
        let value = serde_json::to_value(checked_id(&id).expect_err("bad id type")).unwrap();
        assert_eq!(value["error"]["code"], INVALID_REQUEST, "id {raw}");
        assert_eq!(value["id"], raw, "id {raw} must be echoed verbatim");
    }
}

#[test]
fn string_and_integer_ids_pass_through() {
    for raw in [json!("req-1"), json!(7)] {
        let id = id_of(json!({"jsonrpc": "2.0", "id": raw, "method": "ping"}));
        assert_eq!(checked_id(&id).ok().flatten(), Some(raw));
    }
}

#[test]
fn agent_client_is_capped_at_the_upstream_header_bound() {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, "a".repeat(4096).parse().unwrap());
    let client = agent_client(&headers).expect("present");
    assert_eq!(client.len(), upstream::UPSTREAM_MAX_BYTES);
}

#[test]
fn agent_client_prefers_user_agent_and_keeps_short_values() {
    let mut headers = HeaderMap::new();
    assert_eq!(agent_client(&headers), None);
    headers.insert(MCP_CLIENT_HEADER, "mcp-cli/1.0".parse().unwrap());
    assert_eq!(agent_client(&headers).as_deref(), Some("mcp-cli/1.0"));
    headers.insert(USER_AGENT, "claude-code/2.1".parse().unwrap());
    assert_eq!(agent_client(&headers).as_deref(), Some("claude-code/2.1"));
}
