use super::*;
use serde_json::json;

#[test]
fn detects_notification_by_missing_id() {
    let notification: Request =
        serde_json::from_value(json!({"jsonrpc": "2.0", "method": "x"})).unwrap();
    assert!(notification.is_notification());
    assert!(matches!(notification.id, RequestId::Absent));

    let request: Request =
        serde_json::from_value(json!({"jsonrpc": "2.0", "id": 1, "method": "x"})).unwrap();
    assert!(!request.is_notification());
    assert!(matches!(request.id, RequestId::Present(_)));
}

/// `"id": null` is *not* a notification — the member is present,
/// just explicitly null, which MCP forbids for requests. Preserving
/// presence lets the transport reject it as `invalid_request`
/// instead of silently accepting it as a notification.
#[test]
fn distinguishes_explicit_null_id_from_absent_id() {
    let with_null: Request =
        serde_json::from_value(json!({"jsonrpc": "2.0", "id": null, "method": "x"})).unwrap();
    assert!(!with_null.is_notification());
    assert!(with_null.id.is_null());
    assert_eq!(with_null.id.response_id(), Value::Null);

    let absent: Request = serde_json::from_value(json!({"jsonrpc": "2.0", "method": "x"})).unwrap();
    assert!(absent.is_notification());
    assert!(!absent.id.is_null());
}

/// MCP `RequestId` is `string | number` (integer). The parser accepts
/// any JSON value into `Present` so the transport can echo the value
/// back in the error response, but `is_invalid_type` flags the
/// non-conforming cases the transport must reject.
#[test]
fn flags_unsupported_id_types_as_invalid() {
    for id in [json!(true), json!(false), json!([]), json!({}), json!(1.5)] {
        let request: Request =
            serde_json::from_value(json!({"jsonrpc": "2.0", "id": id, "method": "x"})).unwrap();
        assert!(
            request.id.is_invalid_type(),
            "expected {id} to be flagged as invalid MCP RequestId type",
        );
        // Round-tripped verbatim so error responses echo the sender's id.
        assert_eq!(request.id.response_id(), id);
        // Invalid-type is disjoint from notification and null.
        assert!(!request.id.is_notification());
        assert!(!request.id.is_null());
    }
}

#[test]
fn accepts_string_and_integer_ids() {
    for id in [
        json!("req-1"),
        json!(1),
        json!(0),
        json!(-1),
        json!(u64::MAX),
    ] {
        let request: Request =
            serde_json::from_value(json!({"jsonrpc": "2.0", "id": id, "method": "x"})).unwrap();
        assert!(
            !request.id.is_invalid_type(),
            "expected {id} to be accepted as a valid MCP RequestId",
        );
    }
}

#[test]
fn error_response_has_no_result() {
    let response = Response::error(json!(1), ErrorObject::method_not_found("foo"));
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["error"]["code"], METHOD_NOT_FOUND);
    assert!(value.get("result").is_none());
}

/// Golden wire shape: the raw-value result serialises byte-for-byte as
/// the old `Value` tree did (field order kept, compact, no re-escaping).
#[test]
fn success_response_wire_bytes_are_stable() {
    #[derive(Serialize)]
    struct Payload {
        zeta: u8,
        alpha: &'static str,
        nested: Value,
    }
    let payload = Payload {
        zeta: 1,
        alpha: "a \"q\" é",
        nested: json!({"b": [1, 2.5, null], "a": true}),
    };
    let wire = serde_json::to_string(&Response::result(json!("id-1"), &payload)).unwrap();
    assert_eq!(
        wire,
        r#"{"jsonrpc":"2.0","id":"id-1","result":{"zeta":1,"alpha":"a \"q\" é","nested":{"b":[1,2.5,null],"a":true}}}"#
    );
}

#[test]
fn success_response_has_no_error() {
    let response = Response::result(json!(1), &json!({ "ok": true }));
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["result"]["ok"], true);
    assert!(value.get("error").is_none());
}
