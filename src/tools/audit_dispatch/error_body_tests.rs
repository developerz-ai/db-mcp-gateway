//! Unit tests for the spec 03 tool error body.

use super::*;

fn body_of(response: &Response) -> Value {
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["result"]["isError"], true);
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

fn read_error(code: OutcomeCode) -> ToolErrorBody<'static> {
    ToolErrorBody {
        code,
        message: "m",
        write: None,
        elapsed_ms: None,
        detail: ErrorDetail::None,
    }
}

#[test]
fn tool_error_payload_shape() {
    let request_id = Uuid::new_v4();
    let response = tool_error(
        Value::from(7),
        request_id,
        read_error(OutcomeCode::Forbidden),
    );
    // The client's JSON-RPC id stays in the envelope only…
    assert_eq!(serde_json::to_value(&response).unwrap()["id"], 7);
    let body = body_of(&response);
    assert_eq!(body["code"], "forbidden");
    assert_eq!(body["message"], "m");
    // …the body carries the gateway id that keys the audit row.
    assert_eq!(body["request_id"], request_id.to_string());
    assert_eq!(body["retryable"], false);
    assert!(body["hint"].as_str().unwrap().contains("list_servers"));
    // A read's body has no `write`; no timing or cap was given.
    for absent in [
        "write",
        "elapsed_ms",
        "limit",
        "position",
        "db_hint",
        "near_misses",
        "location",
    ] {
        assert!(body.get(absent).is_none(), "{absent}: {body}");
    }
}

/// A write-access call's error body says whether the change is in the
/// target, next to the unchanged `request_id` / `code` / `message`; a write
/// that may be in the target is never retryable.
#[test]
fn tool_error_of_a_write_carries_its_state() {
    for (state, wire, retryable) in [
        (WriteState::NotApplied, "not_applied", true),
        (WriteState::Unknown, "unknown", false),
        (WriteState::Applied, "applied", false),
    ] {
        let body = ToolErrorBody {
            write: Some(state),
            ..read_error(OutcomeCode::AuditUnavailable)
        };
        let body = body_of(&tool_error(Value::from(1), Uuid::new_v4(), body));
        assert_eq!(body["write"], wire);
        assert_eq!(body["code"], "audit_unavailable");
        assert_eq!(body["message"], "m");
        assert_eq!(body["retryable"], retryable, "{wire}");
    }
}

#[test]
fn tool_error_names_the_cap_and_the_time_spent() {
    let body = ToolErrorBody {
        elapsed_ms: Some(212),
        detail: ErrorDetail::Limit(HitLimit {
            name: "statement_timeout_ms",
            value: 200,
        }),
        ..read_error(OutcomeCode::Timeout)
    };
    let body = body_of(&tool_error(Value::from(1), Uuid::new_v4(), body));
    assert_eq!(body["elapsed_ms"], 212);
    assert_eq!(
        body["limit"],
        serde_json::json!({"name": "statement_timeout_ms", "value": 200})
    );
    assert_eq!(body["retryable"], false);
    assert!(body["hint"].as_str().unwrap().contains("explain"));
}

/// A DB rejection's body says where the DB stopped, its own hint beside the
/// gateway's, and the closest real names.
#[test]
fn tool_error_carries_what_the_db_pointed_at() {
    let rejection = RejectionDetail {
        position: Some(8),
        db_hint: Some("Perhaps you meant to reference the column \"t.email\".".into()),
        near_misses: vec!["email".into()],
    };
    let body = ToolErrorBody {
        detail: ErrorDetail::Rejection(&rejection),
        ..read_error(OutcomeCode::UndefinedObject)
    };
    let body = body_of(&tool_error(Value::from(1), Uuid::new_v4(), body));
    assert_eq!(body["position"], 8);
    assert!(body["db_hint"].as_str().unwrap().contains("t.email"));
    assert!(body["hint"].as_str().unwrap().contains("describe_schema"));
    assert_eq!(body["near_misses"], serde_json::json!(["email"]));
}

/// Absent DB detail is omitted, never sent as `null` or `[]`.
#[test]
fn tool_error_omits_empty_db_detail() {
    let rejection = RejectionDetail::default();
    let body = ToolErrorBody {
        detail: ErrorDetail::Rejection(&rejection),
        ..read_error(OutcomeCode::SyntaxError)
    };
    let body = body_of(&tool_error(Value::from(1), Uuid::new_v4(), body));
    for absent in ["position", "db_hint", "near_misses"] {
        assert!(body.get(absent).is_none(), "{absent}: {body}");
    }
}

#[test]
fn tool_error_names_where_the_parser_stopped() {
    let body = ToolErrorBody {
        detail: ErrorDetail::Location(SqlLocation {
            line: 2,
            column: 25,
        }),
        ..read_error(OutcomeCode::ForbiddenSql)
    };
    let body = body_of(&tool_error(Value::from(1), Uuid::new_v4(), body));
    assert_eq!(
        body["location"],
        serde_json::json!({"line": 2, "column": 25})
    );
}

/// Every code a client can see has a hint; only the transient ones are
/// retryable.
#[test]
fn every_client_code_has_a_hint() {
    use OutcomeCode::*;
    for code in [
        Forbidden,
        ForbiddenSql,
        PermissionDenied,
        UndefinedObject,
        InvalidArguments,
        ReasonRequired,
        Timeout,
        SyntaxError,
        Unavailable,
        UnsupportedBackend,
        Internal,
        Cancelled,
        AuditUnavailable,
    ] {
        assert!(!hint(code).is_empty(), "{code}");
        let transient = matches!(code, Unavailable | AuditUnavailable | Cancelled);
        assert_eq!(retryable(code, None), transient, "{code}");
    }
}
