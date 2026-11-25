//! The statement bounds over HTTP: past one, `forbidden_sql` and its audit
//! row; at the length cap, the target's own answer and its audit row. Either
//! way the same gateway serves the next call.

use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::calls_for_request;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::config_yaml;

const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }

permissions:
  - group: engineers
    grants:
      - { server: target, database: app, action: query_read }
"#;

const CAP: usize = 64 * 1024;

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("guardbounds-{}", Uuid::new_v4().simple()),
        email: "guard-bounds@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&config_yaml(YAML), user).await
}

/// One tool call's answer: the gateway `request_id` (the `x-request-id`
/// header, the key of this call's own audit row) and the tool result.
#[derive(Debug)]
struct Called {
    tool: &'static str,
    request_id: String,
    is_error: bool,
    body: Value,
}

async fn call(gateway: &LoggedInGateway, tool: &'static str, sql: &str) -> Called {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool,
                        "arguments": { "server": "target", "database": "app", "sql": sql } }
        }))
        .send()
        .await
        .expect("gateway answers");
    let request_id = http.headers()["x-request-id"]
        .to_str()
        .expect("x-request-id is text")
        .to_owned();
    let response: Value = http.json().await.expect("JSON-RPC body");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result text: {response}"));
    Called {
        tool,
        request_id,
        is_error: response["result"]["isError"] == true,
        body: serde_json::from_str(text).expect("JSON body"),
    }
}

/// The one audit row of `called`, found by its own `request_id` so an earlier
/// call's row can never stand in for it, carries `outcome` and names the
/// signed-in user and the tool.
async fn assert_audited(gateway: &LoggedInGateway, called: &Called, outcome: &str) {
    let rows = calls_for_request(&gateway.state_db, &called.request_id).await;
    let outcomes: Vec<_> = rows.iter().map(|(outcome, _)| outcome.as_str()).collect();
    assert_eq!(outcomes, [outcome], "{}", called.body);
    let caller: (String, String) =
        sqlx::query_as("SELECT user_sub, tool FROM audit_calls WHERE request_id = $1")
            .bind(&called.request_id)
            .fetch_one(&gateway.state_db)
            .await
            .expect("audit row");
    let expected = (gateway.user_sub.clone(), called.tool.to_string());
    assert_eq!(caller, expected, "{}", called.body);
}

async fn assert_refused(gateway: &LoggedInGateway, called: &Called, code: &str, names: &str) {
    let body = &called.body;
    assert!(called.is_error, "{body}");
    assert_eq!(body["code"], code, "{body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(message.contains(names), "{names:?} in {body}");
    assert_eq!(body["request_id"], called.request_id.as_str(), "{body}");
    assert_audited(gateway, called, code).await;
}

async fn assert_still_serving(gateway: &LoggedInGateway) {
    let called = call(gateway, "run_query", "SELECT 41 + 1 AS n").await;
    assert!(!called.is_error, "{}", called.body);
    assert_eq!(called.body["rows"], json!([[42]]), "{}", called.body);
    assert_audited(gateway, &called, "success").await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_statement_past_a_bound_is_refused_and_audited_and_the_next_call_runs() {
    let gateway = boot().await;
    let joins = format!("SELECT 1 FROM t{}", " JOIN t".repeat(9000));
    let selects = vec!["SELECT 1"; 2000].join(" UNION ALL ");
    for (sql, names) in [(joins, "512 joins"), (selects, "1024 SELECTs")] {
        for tool in ["run_query", "explain"] {
            let called = call(&gateway, tool, &sql).await;
            assert_refused(&gateway, &called, "forbidden_sql", names).await;
            assert_still_serving(&gateway).await;
        }
    }
}

/// What the target makes of a chain the guard admitted.
#[derive(Debug, Clone, Copy)]
enum Target {
    Answers(bool),
    /// With this SQLSTATE, never one of the guard's codes.
    Rejects(&'static str),
}

/// `(opening, repeated part, the target's decision)`.
const CHAINS: &[(&str, &str, Target)] = &[
    ("SELECT true", " AND true", Target::Answers(true)),
    ("SELECT false", " OR false", Target::Answers(false)),
    ("SELECT 1", "+1", Target::Rejects("54001")),
    ("SELECT 'x'", "||'x'", Target::Rejects("54001")),
    ("SELECT 1", "::int", Target::Rejects("54001")),
    ("SELECT (ARRAY[1])", "[1]", Target::Rejects("54000")),
];

/// Long operator chains pass the guard; the target decides.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_chain_at_the_length_cap_is_answered_and_audited_and_the_next_call_runs() {
    let gateway = boot().await;
    for (opening, part, target) in CHAINS {
        let links = part.repeat((CAP - opening.len()) / part.len());
        let mut sql = format!("{opening}{links}");
        sql.push_str(&" ".repeat(CAP - sql.len()));
        for tool in ["run_query", "explain"] {
            let called = call(&gateway, tool, &sql).await;
            match target {
                Target::Answers(value) => {
                    assert!(!called.is_error, "{part:?} {tool}: {}", called.body);
                    if tool == "run_query" {
                        assert_eq!(called.body["rows"], json!([[value]]), "{part:?}");
                    }
                    assert_audited(&gateway, &called, "success").await;
                }
                Target::Rejects(sqlstate) => {
                    let names = format!("the target DB rejected the SQL: {sqlstate} ");
                    assert_refused(&gateway, &called, "syntax_error", &names).await;
                }
            }
            assert_still_serving(&gateway).await;
        }
    }
}
