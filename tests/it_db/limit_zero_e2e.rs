//! `limit: 0` on `run_query` and `sample_table` is `invalid_arguments`
//! (spec 03 §Errors), not an empty result that reads as "no rows": the
//! JSON-RPC `invalid_params` envelope on the wire, an audit row recording the
//! rejection, and no intent — the target is never reached.
//!
//! Needs the target Postgres (`bin/dev up`).

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mcp::call_tool;
use serde_json::json;

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
  - group: readers
    grants:
      - { server: target, database: app, action: query_read }
"#;

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("limit-zero-{}", uuid::Uuid::new_v4().simple()),
        email: "limit-zero@example.com".into(),
        groups: vec!["readers".into()],
    };
    spawn_logged_in(&crate::common::pg_target::config_yaml(YAML), user).await
}

async fn intents_of(gw: &LoggedInGateway) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_call_intents WHERE user_sub = $1")
        .bind(&gw.user_sub)
        .fetch_one(&gw.state_db)
        .await
        .expect("intent count")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn zero_limit_is_invalid_arguments_and_audited() {
    let gw = boot().await;
    for (tool, arguments) in [
        (
            "run_query",
            json!({ "server": "target", "database": "app", "sql": "SELECT 1", "limit": 0 }),
        ),
        (
            "sample_table",
            json!({ "server": "target", "database": "app", "table": "t", "limit": 0 }),
        ),
    ] {
        let resp = call_tool(&gw, tool, arguments).await;
        assert_eq!(resp["error"]["code"], -32602, "{tool}: {resp}");
        assert_eq!(
            resp["error"]["message"], "`limit` must be at least 1",
            "{tool}: {resp}"
        );

        let row = latest_audit(&gw.state_db, &gw.user_sub, tool, tool).await;
        assert_eq!(row.outcome, "invalid_arguments", "{tool}");
        assert_eq!(row.server.as_deref(), Some("target"), "{tool}");
        assert_eq!(
            row.error_message.as_deref(),
            Some("`limit` must be at least 1"),
            "{tool}"
        );
    }
    assert_eq!(
        intents_of(&gw).await,
        0,
        "a refused limit never reaches the target"
    );

    // `limit: 1` still runs: the bound is 0, not small values.
    let resp = call_tool(
        &gw,
        "run_query",
        json!({ "server": "target", "database": "app", "sql": "SELECT 1", "limit": 1 }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", "limit 1").await;
    assert_eq!(row.outcome, "success");
}
