//! The guard's bounds over HTTP: a statement past one, or not read to its
//! end, is `forbidden_sql` with its audit row; at the length cap, the target's
//! own answer and its audit row. Either way the same gateway serves the next
//! call.

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

/// What becomes of a chain at the length cap.
#[derive(Debug, Clone, Copy)]
enum Decision {
    /// The target's answer.
    Answers(bool),
    /// The target's SQLSTATE, never one of the guard's codes.
    Rejects(&'static str),
    /// The guard's: deeper than Postgres's own parse tree goes.
    TooDeep,
}

/// `(opening, repeated part, the decision)`.
const CHAINS: &[(&str, &str, Decision)] = &[
    ("SELECT true", " AND true", Decision::Answers(true)),
    ("SELECT false", " OR false", Decision::Answers(false)),
    ("SELECT 1", "+1", Decision::TooDeep),
    ("SELECT 'x'", "||'x'", Decision::TooDeep),
    ("SELECT 1", "::int", Decision::TooDeep),
    ("SELECT (ARRAY[1])", "[1]", Decision::Rejects("54000")),
];

/// Flat chains pass the guard and the target decides; nested ones never reach it.
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
                Decision::Answers(value) => {
                    assert!(!called.is_error, "{part:?} {tool}: {}", called.body);
                    if tool == "run_query" {
                        assert_eq!(called.body["rows"], json!([[value]]), "{part:?}");
                    }
                    assert_audited(&gateway, &called, "success").await;
                }
                Decision::Rejects(sqlstate) => {
                    let names = format!("the target DB rejected the SQL: {sqlstate} ");
                    assert_refused(&gateway, &called, "syntax_error", &names).await;
                }
                Decision::TooDeep => {
                    let names = "nests too deeply";
                    assert_refused(&gateway, &called, "forbidden_sql", names).await;
                }
            }
            assert_still_serving(&gateway).await;
        }
    }
}

/// `(sql, its one value)`: sizes generated queries reach.
fn long_queries() -> Vec<(String, Value)> {
    let case = "CASE WHEN false THEN 0 ELSE ";
    let joins: String = (0..200)
        .map(|i| format!(" CROSS JOIN LATERAL (SELECT 1 AS x) u{i}"))
        .collect();
    vec![
        (format!("SELECT 1{}", "+1".repeat(1000)), json!(1001)),
        (
            format!("SELECT length(''{})", "||'x'".repeat(1000)),
            json!(1000),
        ),
        (
            format!("SELECT {}7{}", case.repeat(100), " END".repeat(100)),
            json!(7),
        ),
        (format!("SELECT u199.x FROM (SELECT 1) t{joins}"), json!(1)),
        (
            format!(
                "SELECT count(*) FROM (SELECT 1{}) u",
                " UNION ALL SELECT 2".repeat(500)
            ),
            json!(501),
        ),
        (
            "SELECT substring('abc', 2, 1) || substr('xyz', 1, 1) || trim(BOTH '-' FROM '-q-')"
                .to_string(),
            json!("bxq"),
        ),
    ]
}

/// Both parsers read these alike, and the target answers them.
#[tokio::test]
#[serial_test::parallel(world)]
async fn long_generated_queries_are_answered_and_audited() {
    let gateway = boot().await;
    for (sql, value) in long_queries() {
        let called = call(&gateway, "run_query", &sql).await;
        assert!(!called.is_error, "{:.60}…: {}", sql, called.body);
        assert_eq!(called.body["rows"], json!([[value]]), "{sql:.60}…");
        assert_audited(&gateway, &called, "success").await;
        let called = call(&gateway, "explain", &sql).await;
        assert!(!called.is_error, "{:.60}…: {}", sql, called.body);
        assert_audited(&gateway, &called, "success").await;
    }
}

/// `(sql, what the message names)`.
const REFUSED: &[(&str, &str)] = &[
    ("SELECT 1 END", "could not parse SQL at line 1, column 10"),
    ("SELECT 1 END, pg_notify('c', 'p')", "column 10"),
    ("SELECT 1 END FROM pg_class FOR UPDATE", "column 10"),
    ("SELECT 1 end; SELECT 2", "column 10"),
    ("SELECT TREAT(1 AS pg_advisory_lock)", "`treat`"),
    ("SELECT a AND FOR UPDATE", "FOR UPDATE/SHARE"),
    ("SELECT * FROM (TABLE cron.job) j", "`cron.*`"),
];

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_statement_not_read_to_its_end_is_refused_and_audited_and_the_next_call_runs() {
    let gateway = boot().await;
    for (sql, names) in REFUSED {
        for tool in ["run_query", "explain"] {
            let called = call(&gateway, tool, sql).await;
            assert_refused(&gateway, &called, "forbidden_sql", names).await;
            assert_still_serving(&gateway).await;
        }
    }
}

/// The same words as labels and columns reach the target and its answer.
#[tokio::test]
#[serial_test::parallel(world)]
async fn labels_named_like_keywords_are_answered_and_audited() {
    let gateway = boot().await;
    for (sql, rows) in [
        ("SELECT 1 AS end, 2 AS \"END\"", json!([[1, 2]])),
        (
            "SELECT CASE WHEN true THEN 1 END AS end, s.schedule FROM (VALUES (2)) AS s(schedule)",
            json!([[1, 2]]),
        ),
        (
            "SELECT s.\"end\" AS into FROM (SELECT 3 AS end) s;",
            json!([[3]]),
        ),
    ] {
        let called = call(&gateway, "run_query", sql).await;
        assert!(!called.is_error, "{sql}: {}", called.body);
        assert_eq!(called.body["rows"], rows, "{sql}");
        assert_audited(&gateway, &called, "success").await;
    }
}
