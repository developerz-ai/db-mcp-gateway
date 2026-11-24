//! `get_query_history`'s `sql_sha256`: each entry carries the SHA-256 of its
//! stored SQL, and the argument narrows the caller's own history to one
//! statement's runs. Every call asserts its audit row.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::audit::assert_audit_outcome;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mcp::call_tool;

const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: historians
    grants:
      - { server: target, database: app, action: query_read }
      - { server: target, database: app, action: history_read }
"#;

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("history-sha-{}", uuid::Uuid::new_v4().simple()),
        email: "history-sha@example.com".to_string(),
        groups: vec!["historians".to_string()],
    };
    spawn_logged_in(&crate::common::pg_target::config_yaml(YAML), user).await
}

fn hex_sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn history(gw: &LoggedInGateway, extra: Value) -> Value {
    let mut arguments = json!({ "server": "target", "database": "app" });
    for (key, value) in extra.as_object().expect("object") {
        arguments[key] = value.clone();
    }
    call_tool(gw, "get_query_history", arguments).await
}

fn entries(response: &Value) -> Vec<Value> {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("history text: {response}"));
    let body: Value = serde_json::from_str(text).expect("payload is JSON");
    body["entries"].as_array().expect("entries").clone()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn entries_carry_the_hash_and_the_hash_filters_them() {
    let gw = boot().await;
    let (twice, once) = ("SELECT 1 AS twice", "SELECT 2 AS once");
    for sql in [twice, once, twice] {
        let arguments = json!({ "server": "target", "database": "app", "sql": sql });
        let resp = call_tool(&gw, "run_query", arguments).await;
        assert_eq!(resp["result"]["isError"], false, "{resp}");
        assert_audit_outcome(&gw.state_db, &gw.user_sub, "run_query", "success", sql).await;
    }

    let all = entries(&history(&gw, json!({})).await);
    assert_eq!(all.len(), 3, "{all:?}");
    for entry in &all {
        let sql = entry["sql"].as_str().expect("sql");
        assert_eq!(entry["sql_sha256"], hex_sha256(sql), "{entry}");
    }
    assert_audit_outcome(
        &gw.state_db,
        &gw.user_sub,
        "get_query_history",
        "success",
        "all",
    )
    .await;

    // Either case of hex is the same filter.
    for hash in [hex_sha256(twice), hex_sha256(twice).to_uppercase()] {
        let runs = entries(&history(&gw, json!({ "sql_sha256": hash })).await);
        assert_eq!(runs.len(), 2, "{runs:?}");
        assert!(runs.iter().all(|entry| entry["sql"] == twice), "{runs:?}");
        assert_audit_outcome(
            &gw.state_db,
            &gw.user_sub,
            "get_query_history",
            "success",
            "hash",
        )
        .await;
    }
    let none = entries(&history(&gw, json!({ "sql_sha256": hex_sha256("SELECT 3") })).await);
    assert!(none.is_empty(), "{none:?}");
}

/// The filter narrows the caller's own history; another identity's runs of
/// the same statement never match.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_hash_filter_stays_within_the_callers_history() {
    let (mine, theirs) = (boot().await, boot().await);
    let sql = format!("SELECT '{}' AS shared", uuid::Uuid::new_v4());
    let arguments = json!({ "server": "target", "database": "app", "sql": sql });
    let resp = call_tool(&theirs, "run_query", arguments).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert_audit_outcome(
        &theirs.state_db,
        &theirs.user_sub,
        "run_query",
        "success",
        "theirs",
    )
    .await;

    let runs = entries(&history(&mine, json!({ "sql_sha256": hex_sha256(&sql) })).await);
    assert!(runs.is_empty(), "{runs:?}");
    assert_audit_outcome(
        &mine.state_db,
        &mine.user_sub,
        "get_query_history",
        "success",
        "mine",
    )
    .await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_malformed_hash_is_invalid_arguments_and_audited() {
    let gw = boot().await;
    for bad in ["abc", &"g".repeat(64), &"a".repeat(65)] {
        let resp = history(&gw, json!({ "sql_sha256": bad })).await;
        assert_eq!(resp["error"]["code"], -32602, "{bad}: {resp}");
        assert_audit_outcome(
            &gw.state_db,
            &gw.user_sub,
            "get_query_history",
            "invalid_arguments",
            bad,
        )
        .await;
    }
}
