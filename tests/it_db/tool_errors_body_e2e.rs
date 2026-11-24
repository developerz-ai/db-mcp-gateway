//! E2E for the spec 03 tool error body over real MCP calls: besides
//! `request_id` / `code` / `message`, every error says whether the same
//! call may succeed again (`retryable`), what to do next (`hint`), how long
//! it ran (`elapsed_ms`) and, when a gateway cap stopped it, which (`limit`).

use serde_json::json;

use crate::agent_walk_support::{Agent, GRANT_TIMEOUT_MS};

#[tokio::test]
#[serial_test::parallel(world)]
async fn timeout_body_names_the_budget_and_points_at_explain() {
    let agent = Agent::boot().await;
    let args = json!({"server": "target", "database": "app", "sql": "SELECT pg_sleep(2)"});
    let called = agent.call("run_query", args).await;

    assert!(called.is_error(), "{:?}", called.response);
    let body = &called.payload;
    assert_eq!(body["code"], "timeout", "{body}");
    assert_eq!(body["request_id"], called.request_id.as_str());
    assert_eq!(body["retryable"], false);
    assert!(body["hint"].as_str().unwrap().contains("explain"), "{body}");
    assert_eq!(
        body["limit"],
        json!({"name": "statement_timeout_ms", "value": GRANT_TIMEOUT_MS})
    );
    let elapsed = body["elapsed_ms"].as_u64().expect("elapsed_ms is a number");
    assert!(elapsed >= GRANT_TIMEOUT_MS, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("(300 ms)"), "{message}");
    assert!(message.contains("explain"), "{message}");
    // A read carries no `write`.
    assert!(body.get("write").is_none(), "{body}");

    let (outcome, audited) = agent.audit_of(&called).await;
    assert_eq!(outcome, "timeout");
    assert_eq!(
        audited.as_deref(),
        Some(message),
        "the audit row keeps the text sent"
    );
}

/// An unknown server, an unknown database and a denied one answer the same
/// message and hint, so a caller cannot probe for names; the hint names the
/// discovery tools.
#[tokio::test]
#[serial_test::parallel(world)]
async fn forbidden_reads_the_same_for_unknown_and_denied() {
    let agent = Agent::boot().await;
    let mut bodies = Vec::new();
    for (server, database) in [("hidden", "app"), ("nosuch", "app"), ("target", "nosuch")] {
        let args = json!({"server": server, "database": database, "sql": "SELECT 1"});
        let called = agent.call("run_query", args).await;
        assert!(called.is_error(), "{:?}", called.response);
        assert_eq!(called.payload["code"], "forbidden");
        assert_eq!(called.payload["retryable"], false);
        agent.assert_audited(&called, "forbidden").await;
        bodies.push(called.payload);
    }
    let hint = bodies[0]["hint"].as_str().unwrap();
    assert!(
        hint.contains("list_servers") && hint.contains("list_databases"),
        "{hint}"
    );
    for body in &bodies[1..] {
        assert_eq!(body["message"], bodies[0]["message"]);
        assert_eq!(body["hint"], bodies[0]["hint"]);
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_wrong_name_points_at_describe_schema() {
    let agent = Agent::boot().await;
    let args = json!({
        "server": "target",
        "database": "app",
        "sql": "SELECT * FROM no_such_table_for_hints"
    });
    let called = agent.call("run_query", args).await;

    let body = &called.payload;
    assert_eq!(body["code"], "undefined_object", "{body}");
    assert_eq!(body["retryable"], false);
    assert!(
        body["hint"].as_str().unwrap().contains("describe_schema"),
        "{body}"
    );
    assert!(body.get("limit").is_none(), "no cap was hit: {body}");
    agent.assert_audited(&called, "undefined_object").await;
}
