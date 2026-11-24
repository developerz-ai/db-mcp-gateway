//! A write committed in the target, then its completion row failed (plan 101
//! U1). The client must not read "request rejected" as "nothing happened" —
//! a blind retry would write twice — so the error body says the write is in
//! (`write: "applied"`, the may-have-committed note in `message`), and the
//! call is still accounted for: the intent is reaped as `abandoned`,
//! `access: write`.
//!
//! The completion insert is made to fail by a trigger on `audit_calls` scoped
//! to this test's user — every completion and fallback row of that user is
//! refused, the reaper's `abandoned` row is let through. Serial: it alters
//! `audit_calls` and runs a reaper sweep.
//!
//! Needs the state and target Postgres (`bin/dev up`).

use std::time::Duration;

use crate::common::audit::{calls_for_request, find_intent, latest_audit};
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::target_db_url;
use crate::common::gateway::spawn_logged_in;
use crate::common::idp::MockUser;
use db_mcp_gateway::audit::intent::WRITE_MAY_HAVE_COMMITTED;
use db_mcp_gateway::audit::reaper::{self, ReapCursor};
use serde_json::{Value, json};
use sqlx::PgPool;

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
        role: dbmcp_test_ro
        password: ro-dev-only
        write_role: app
        write_password: app-dev-only

permissions:
  - group: writers
    grants:
      - { server: target, database: app, action: query_write }
"#;

async fn execute(pool: &PgPool, sql: String) {
    sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
        .execute(pool)
        .await
        .unwrap_or_else(|err| panic!("{sql}: {err}"));
}

/// Refuse every `audit_calls` insert of `sub` but the reaper's.
async fn fail_completions_of(pool: &PgPool, trigger: &str, sub: &str) {
    execute(
        pool,
        format!(
            "CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'completion refused by test'; END $$"
        ),
    )
    .await;
    execute(
        pool,
        format!(
            "CREATE TRIGGER {trigger} BEFORE INSERT ON audit_calls FOR EACH ROW \
             WHEN (NEW.user_sub = '{sub}' AND NEW.outcome <> 'abandoned') \
             EXECUTE FUNCTION {trigger}()"
        ),
    )
    .await;
}

async fn restore_completions(pool: &PgPool, trigger: &str) {
    execute(pool, format!("DROP TRIGGER {trigger} ON audit_calls")).await;
    execute(pool, format!("DROP FUNCTION {trigger}()")).await;
}

fn body(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text content: {response}"));
    serde_json::from_str(text).expect("error body is JSON")
}

#[tokio::test]
#[serial_test::serial(world)]
async fn committed_write_with_a_failed_completion_says_it_is_in() {
    crate::common::pg_target::ensure_read_role().await;
    let user = MockUser {
        sub: format!("u1-write-{}", uuid::Uuid::new_v4().simple()),
        email: "u1-write@example.com".into(),
        groups: vec!["writers".into()],
    };
    let gw = spawn_logged_in(&crate::common::pg_target::config_yaml(YAML), user).await;
    let target = PgPool::connect(&target_db_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let table = format!("u1_write_{}", uuid::Uuid::new_v4().simple());
    execute(
        &target,
        format!("CREATE TABLE \"{table}\" (id bigint PRIMARY KEY)"),
    )
    .await;
    let trigger = format!("u1_refuse_{}", uuid::Uuid::new_v4().simple());
    fail_completions_of(&gw.state_db, &trigger, &gw.user_sub).await;

    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&gw.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "run_query", "arguments": {
                "server": "target", "database": "app",
                "sql": format!("INSERT INTO \"{table}\" (id) VALUES (1)"),
            }}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(response["result"]["isError"], true, "{response}");
    let error = body(&response);
    assert_eq!(error["code"], "audit_unavailable", "{error}");
    assert_eq!(error["write"], "applied", "{error}");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("audit write failed; request rejected"),
        "{message}"
    );
    assert!(message.contains(WRITE_MAY_HAVE_COMMITTED), "{message}");

    // The write really is in the target: the flag is not a guess.
    let rows: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM \"{table}\""
    )))
    .fetch_one(&target)
    .await
    .expect("count");
    assert_eq!(rows, 1);

    // Accounted for: the intent recorded write access and, past the grace,
    // is reaped as `abandoned` saying so.
    let request_id = error["request_id"].as_str().expect("request_id").to_owned();
    assert_eq!(
        find_intent(&gw.state_db, &request_id).await.as_deref(),
        Some("write")
    );
    sqlx::query(
        "UPDATE audit_call_intents SET occurred_at = now() - interval '2 hours' \
         WHERE request_id = $1",
    )
    .bind(&request_id)
    .execute(&gw.state_db)
    .await
    .expect("age the intent past the grace");
    reaper::run_once(
        &gw.state_db,
        Duration::from_secs(3600),
        &mut ReapCursor::default(),
    )
    .await
    .expect("reaper sweep runs");
    let calls = calls_for_request(&gw.state_db, &request_id).await;
    restore_completions(&gw.state_db, &trigger).await;
    assert_eq!(calls.len(), 1, "{calls:?}");
    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", "reaped write").await;
    assert_eq!(row.request_id, request_id);
    assert_eq!(row.outcome, "abandoned");
    let note = row.error_message.unwrap_or_default();
    assert!(note.contains("access: write"), "{note}");

    delete_audit_calls(&gw.state_db, &gw.user_sub).await;
    execute(&target, format!("DROP TABLE \"{table}\"")).await;
}
