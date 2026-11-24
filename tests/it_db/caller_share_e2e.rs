//! Per-identity pool share through the real `tools/call` path: `dispatch_call`
//! scopes every tool to its caller, so one identity filling its share of a
//! database's pool with slow queries leaves a connection for everyone else.
//! The adapter-level property is `exec_isolation_real_db`; this proves the
//! gateway wires the caller scope around a real HTTP dispatch.

use std::time::{Duration, Instant};

use crate::common::audit::assert_audit_outcome;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::{state_pool, target_db_url};
use crate::common::gateway::{GatewayBuilder, TestGateway};
use crate::common::pg_target::config_yaml;
use db_mcp_gateway::auth::jwt;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// A pool of two: each caller's share is one connection.
const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: caller-share e2e
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only
        pool: { max_connections: 2 }

permissions:
  - group: engineers
    grants:
      - server: target
        database: app
        action: query_read
        constraints:
          statement_timeout_ms: 10000
"#;

const SLEEP_SECS: u64 = 3;
const SLEEP: Duration = Duration::from_secs(SLEEP_SECS);

async fn bearer(gw: &TestGateway, sub: &str) -> String {
    let groups = ["engineers".to_string()];
    let ttl = Duration::from_secs(600);
    let session = gw
        .sessions
        .create(sub, "share-e2e@example.com", &groups, ttl, None)
        .await
        .expect("create session");
    jwt::issue(&gw.auth_config.session_signing_key, session.id, sub, ttl).expect("issue JWT")
}

/// `run_query` over HTTP; returns the decoded tool payload and how long the
/// call took.
async fn run_query(url: &str, bearer: &str, sql: &str) -> (Value, Duration) {
    let started = Instant::now();
    let response: Value = reqwest::Client::new()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .timeout(Duration::from_secs(20))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_query",
                "arguments": { "server": "target", "database": "app", "sql": sql }
            }
        }))
        .send()
        .await
        .expect("request sent")
        .json()
        .await
        .expect("JSON-RPC body");
    let elapsed = started.elapsed();
    assert_eq!(response["result"]["isError"], false, "{response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    (serde_json::from_str(text).expect("payload JSON"), elapsed)
}

/// Target backends currently running a statement that contains `marker`.
async fn running(monitor: &PgPool, marker: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE state = 'active' AND pid <> pg_backend_pid() AND query LIKE '%' || $1 || '%'",
    )
    .bind(marker)
    .fetch_one(monitor)
    .await
    .expect("pg_stat_activity readable")
}

async fn successes(state: &PgPool, sub: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_calls \
         WHERE user_sub = $1 AND tool = 'run_query' AND outcome = 'success'",
    )
    .bind(sub)
    .fetch_one(state)
    .await
    .expect("audit_calls readable")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn one_identity_at_its_share_leaves_a_connection_for_another() {
    let gw = GatewayBuilder::new(&config_yaml(YAML))
        .spawn(state_pool().await)
        .await;
    let x = format!("share-x-{}", Uuid::new_v4().simple());
    let y = format!("share-y-{}", Uuid::new_v4().simple());
    let (x_bearer, y_bearer) = (bearer(&gw, &x).await, bearer(&gw, &y).await);
    let monitor = PgPoolOptions::new()
        .max_connections(1)
        .connect(&target_db_url())
        .await
        .expect("target-db reachable");

    let marker = format!("share_{}", Uuid::new_v4().simple());
    let sleep_sql = format!("SELECT pg_sleep({SLEEP_SECS}), '{marker}'::text AS m");
    let sleepers: Vec<_> = (0..2)
        .map(|_| {
            let (url, bearer, sql) = (gw.url.clone(), x_bearer.clone(), sleep_sql.clone());
            tokio::spawn(async move { run_query(&url, &bearer, &sql).await.1 })
        })
        .collect();

    let deadline = Instant::now() + Duration::from_secs(5);
    while running(&monitor, &marker).await == 0 {
        assert!(Instant::now() < deadline, "X's first sleep never started");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (y_body, y_waited) = run_query(&gw.url, &y_bearer, "SELECT 1::int4 AS n").await;
    assert_eq!(y_body["rows"][0][0], json!(1), "{y_body}");
    assert!(
        y_waited < SLEEP / 2,
        "Y waited {y_waited:?} behind X's queries"
    );
    assert_eq!(
        running(&monitor, &marker).await,
        1,
        "X's second query must wait for X's own share, not take Y's connection"
    );

    let mut x_elapsed = Vec::new();
    for sleeper in sleepers {
        x_elapsed.push(sleeper.await.expect("join"));
    }
    x_elapsed.sort();
    assert!(
        x_elapsed[1] >= SLEEP * 2 - Duration::from_millis(500),
        "X's second call ran beside its first: {x_elapsed:?}"
    );

    assert_eq!(successes(&gw.state_db, &x).await, 2, "X's calls audited");
    assert_eq!(successes(&gw.state_db, &y).await, 1, "Y's call audited");
    assert_audit_outcome(&gw.state_db, &y, "run_query", "success", "Y's call").await;
    delete_audit_calls(&gw.state_db, &x).await;
    delete_audit_calls(&gw.state_db, &y).await;
}
