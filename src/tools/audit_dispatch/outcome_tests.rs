//! Unit tests for the spec 03 outcome mapping.

use super::*;

#[test]
fn tool_error_payload_shape() {
    let request_id = Uuid::new_v4();
    let response = tool_error(
        Value::from(7),
        request_id,
        OutcomeCode::Forbidden,
        "nope",
        None,
    );
    let value = serde_json::to_value(&response).unwrap();
    // The client's JSON-RPC id stays in the envelope only…
    assert_eq!(value["id"], 7);
    assert_eq!(value["result"]["isError"], true);
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["code"], "forbidden");
    assert_eq!(body["message"], "nope");
    // …the body carries the gateway id that keys the audit row.
    assert_eq!(body["request_id"], request_id.to_string());
    // A read's body has no `write` field: it is added only for writes.
    assert!(body.get("write").is_none(), "{body}");
}

/// A write-access call's error body says whether the change is in the
/// target, next to the unchanged `request_id` / `code` / `message`.
#[test]
fn tool_error_of_a_write_carries_its_state() {
    for (state, wire) in [
        (WriteState::NotApplied, "not_applied"),
        (WriteState::Unknown, "unknown"),
        (WriteState::Applied, "applied"),
    ] {
        let response = tool_error(
            Value::from(1),
            Uuid::new_v4(),
            OutcomeCode::AuditUnavailable,
            "m",
            Some(state),
        );
        let value = serde_json::to_value(&response).unwrap();
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["write"], wire);
        assert_eq!(body["code"], "audit_unavailable");
        assert_eq!(body["message"], "m");
    }
}

#[test]
fn tool_success_payload_shape() {
    let response = tool_success(Value::from(1), r#"{"hello":"world"}"#.to_string());
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["id"], 1);
    assert_eq!(value["result"]["isError"], false);
    assert_eq!(
        value["result"]["content"][0]["text"],
        r#"{"hello":"world"}"#
    );
}

#[test]
fn error_outcome_mirrors_message_into_audit() {
    let outcome = error_outcome(OutcomeCode::Forbidden, "no grants");
    assert_eq!(outcome.code, OutcomeCode::Forbidden);
    assert_eq!(outcome.error_message.as_deref(), Some("no grants"));
    assert!(outcome.row_count.is_none());
}

/// Defense-in-depth backstop: an undispatchable `kind` is now rejected at
/// boot (`config::yaml` validation), so a validated config never reaches
/// `UnsupportedAdapter`. If an internal caller ever does, the tool must
/// still map it to the stable `internal` code with a generic message —
/// never the raw `ServerKind` debug, which could hint at backend topology.
#[test]
fn unsupported_adapter_maps_to_internal_without_leaking_kind() {
    use crate::config::ServerKind;

    let messages = ToolErrorMessages {
        timeout: "t",
        sql_rejected: "s",
        forbidden_prefix: "query",
    };
    let outcome = outcome_from_exec_error(
        ExecError::UnsupportedAdapter(ServerKind::Mysql),
        Instant::now(),
        &messages,
    );
    assert_eq!(outcome.code, OutcomeCode::Internal);
    assert_eq!(
        outcome.error_message.as_deref(),
        Some("server-side configuration error")
    );
    // The backend identity must not ride along into the client-facing text.
    let msg = outcome.error_message.unwrap_or_default().to_lowercase();
    assert!(!msg.contains("mysql"), "{msg}");
}

#[test]
fn indeterminate_commit_is_unavailable_and_says_the_write_may_have_landed() {
    let messages = ToolErrorMessages {
        timeout: "t",
        sql_rejected: "s",
        forbidden_prefix: "query",
    };
    let outcome =
        outcome_from_exec_error(ExecError::CommitIndeterminate, Instant::now(), &messages);
    assert_eq!(outcome.code, OutcomeCode::Unavailable);
    let message = outcome.error_message.unwrap_or_default();
    assert!(message.contains(WRITE_MAY_HAVE_COMMITTED), "{message}");
}

#[test]
fn invalid_arguments_uses_the_invalid_params_envelope() {
    let outcome = invalid_arguments(Value::from(3), "`limit` must be at least 1");
    assert_eq!(outcome.code, OutcomeCode::InvalidArguments);
    let Reply::Response(response) = &outcome.reply else {
        panic!("invalid arguments keep the JSON-RPC envelope");
    };
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["error"]["code"], -32602);
    assert_eq!(
        outcome.error_message.as_deref(),
        Some("`limit` must be at least 1")
    );
}

#[test]
fn success_outcome_carries_row_metadata() {
    let outcome = success_outcome(
        Value::from(1),
        "{}".to_string(),
        Some(42),
        Some(100),
        Some(true),
    );
    assert_eq!(outcome.code, OutcomeCode::Success);
    assert_eq!(outcome.elapsed_ms, Some(42));
    assert_eq!(outcome.row_count, Some(100));
    assert_eq!(outcome.truncated, Some(true));
    assert!(outcome.error_message.is_none());
}

/// A tool the engine does not offer is a stable, documented answer — never
/// `internal`, which spec 03 reserves for bugs.
#[test]
fn not_implemented_maps_to_unsupported_backend() {
    use crate::exec::AdapterKind;

    let messages = ToolErrorMessages {
        timeout: "t",
        sql_rejected: "s",
        forbidden_prefix: "query",
    };
    let outcome = outcome_from_exec_error(
        ExecError::NotImplemented {
            adapter: AdapterKind::Mongo,
            op: "table_stats",
        },
        Instant::now(),
        &messages,
    );
    assert_eq!(outcome.code, OutcomeCode::UnsupportedBackend);
}

#[test]
fn a_write_is_applied_only_when_it_committed() {
    let committed = Ok(ExecResult {
        columns: vec![],
        rows: vec![],
        truncated: false,
        elapsed_ms: 1,
        rows_affected: Some(1),
    });
    assert_eq!(write_state(&committed, false), WriteState::Applied);
    assert_eq!(write_state(&committed, true), WriteState::NotApplied);
    for err in [
        ExecError::Timeout,
        ExecError::Cancelled,
        ExecError::CommitIndeterminate,
    ] {
        assert_eq!(write_state(&Err(err), false), WriteState::Unknown);
    }
    assert_eq!(
        write_state(&Err(ExecError::CommitIndeterminate), true),
        WriteState::NotApplied
    );
    for err in [ExecError::Sql, ExecError::Connection, ExecError::Decode] {
        assert_eq!(write_state(&Err(err), false), WriteState::NotApplied);
    }
}
