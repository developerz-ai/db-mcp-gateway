//! `table_stats`, `db_activity`, `cancel_query` (plan 101 slice 12 step 6)
//! against the real target Postgres: each is audited on success, forbidden
//! and invalid arguments; activity and cancellation are own-identity only;
//! a cancel leaves the victim's own `cancelled` row.
//!
//! Two identities share one gateway: the logged-in human (`inspectors`) and
//! a service token with the same grants (`peers`) — same grants, different
//! identity, so ownership is the only thing that separates them.
//!
//! Needs the target Postgres (`bin/dev up` → :5434).

use std::time::Duration;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};

const PEER_TOKEN: &str =
    "dbmcp_svc_5555555555555555555555555555555555555555555555555555555555555555";

fn yaml(peer: &str) -> String {
    format!(
        r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - {{ name: app, role: app, password: app-dev-only }}

permissions:
  - group: inspectors
    grants:
      - {{ server: target, database: app, action: query_read }}
  - group: peers
    grants:
      - {{ server: target, database: app, action: query_read }}
  - group: historians
    grants:
      - {{ server: target, database: app, action: history_read }}

service_accounts:
  - name: {peer}
    group: peers
    token: {PEER_TOKEN}
"#
    )
}

struct Fixture {
    gw: LoggedInGateway,
    peer: String,
}

impl Fixture {
    async fn new(group: &str) -> Self {
        let peer = format!("peer-{}", uuid::Uuid::new_v4().simple());
        let user = MockUser {
            sub: format!("inspector-{}", uuid::Uuid::new_v4().simple()),
            email: "inspector@example.com".into(),
            groups: vec![group.into()],
        };
        let gw = spawn_logged_in(&yaml(&peer), user).await;
        Self { gw, peer }
    }

    fn peer_sub(&self) -> String {
        format!("service:{}", self.peer)
    }

    async fn call_as(&self, bearer: &str, tool: &str, args: Value) -> Value {
        let mut arguments = json!({ "server": "target", "database": "app" });
        for (key, value) in args.as_object().expect("object") {
            arguments[key] = value.clone();
        }
        reqwest::Client::new()
            .post(format!("{}/mcp", self.gw.url))
            .bearer_auth(bearer)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn call(&self, tool: &str, args: Value) -> Value {
        self.call_as(&self.gw.bearer, tool, args).await
    }

    /// The request id of the caller's in-flight `run_query`, from its intent.
    async fn running_request_id(&self) -> String {
        for _ in 0..50 {
            let found: Option<String> = sqlx::query_scalar(
                "SELECT request_id FROM audit_call_intents \
                 WHERE user_sub = $1 AND tool = 'run_query' \
                 ORDER BY occurred_at DESC LIMIT 1",
            )
            .bind(&self.gw.user_sub)
            .fetch_optional(&self.gw.state_db)
            .await
            .unwrap();
            if let Some(id) = found {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the slow query never recorded its intent");
    }
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text content: {response}"));
    serde_json::from_str(text).expect("payload is valid JSON")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn table_stats_reports_a_table_and_is_audited() {
    let fx = Fixture::new("inspectors").await;
    let target = sqlx::PgPool::connect("postgres://app:app-dev-only@localhost:5434/app")
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let table = format!("stats_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE TABLE \"{table}\" (id bigint PRIMARY KEY)"))
        .execute(&target)
        .await
        .expect("create scratch table");

    let resp = fx.call("table_stats", json!({ "table": table })).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    let columns: Vec<&str> = body["columns"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let at = columns
        .iter()
        .position(|c| *c == "table")
        .expect("table column");
    assert_eq!(body["rows"][0][at], table.as_str(), "{body}");
    let row = latest_audit(&fx.gw.state_db, &fx.gw.user_sub, "table_stats", "stats").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.sql.as_deref(), Some(format!("public.{table}").as_str()));

    sqlx::query(&format!("DROP TABLE \"{table}\""))
        .execute(&target)
        .await
        .expect("drop scratch table");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn introspection_without_a_grant_is_forbidden_and_audited() {
    let fx = Fixture::new("historians").await;
    let id = uuid::Uuid::new_v4().to_string();
    for (tool, args) in [
        ("table_stats", json!({})),
        ("db_activity", json!({})),
        ("cancel_query", json!({ "request_id": id })),
    ] {
        let resp = fx.call(tool, args).await;
        assert_eq!(payload(&resp)["code"], "forbidden", "{tool}: {resp}");
        let row = latest_audit(&fx.gw.state_db, &fx.gw.user_sub, tool, "forbidden").await;
        assert_eq!(row.outcome, "forbidden", "{tool}");
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn cancel_query_rejects_a_malformed_request_id() {
    let fx = Fixture::new("inspectors").await;
    let resp = fx
        .call("cancel_query", json!({ "request_id": "nope" }))
        .await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let row = latest_audit(&fx.gw.state_db, &fx.gw.user_sub, "cancel_query", "bad id").await;
    assert_eq!(row.outcome, "invalid_arguments");
}

/// The owner sees its running query in `db_activity`; a peer with the same
/// grants sees none of it and cannot cancel it; the owner's cancel stops it
/// and the victim call writes its own `cancelled` row.
#[tokio::test]
#[serial_test::parallel(world)]
async fn activity_and_cancel_are_own_identity_only() {
    let fx = std::sync::Arc::new(Fixture::new("inspectors").await);
    let slow = {
        let fx = fx.clone();
        tokio::spawn(async move {
            fx.call("run_query", json!({ "sql": "SELECT pg_sleep(20)" }))
                .await
        })
    };
    let victim = fx.running_request_id().await;

    let mine = payload(&fx.call("db_activity", json!({})).await);
    assert!(
        mine.to_string().contains(&victim),
        "owner sees its query: {mine}"
    );
    let theirs = payload(&fx.call_as(PEER_TOKEN, "db_activity", json!({})).await);
    assert!(
        !theirs.to_string().contains(&victim),
        "peer must not: {theirs}"
    );
    let row = latest_audit(&fx.gw.state_db, &fx.peer_sub(), "db_activity", "peer").await;
    assert_eq!(row.outcome, "success");

    let resp = fx
        .call_as(PEER_TOKEN, "cancel_query", json!({ "request_id": victim }))
        .await;
    assert_eq!(payload(&resp)["code"], "forbidden", "{resp}");
    let row = latest_audit(&fx.gw.state_db, &fx.peer_sub(), "cancel_query", "peer").await;
    assert_eq!(row.outcome, "forbidden");

    let resp = fx
        .call("cancel_query", json!({ "request_id": victim }))
        .await;
    assert_eq!(payload(&resp)["cancelled"], true, "{resp}");
    let row = latest_audit(&fx.gw.state_db, &fx.gw.user_sub, "cancel_query", "owner").await;
    assert_eq!(row.outcome, "success");

    let victim_resp = tokio::time::timeout(Duration::from_secs(10), slow)
        .await
        .expect("cancelled query returns promptly")
        .expect("task");
    assert_eq!(payload(&victim_resp)["code"], "cancelled", "{victim_resp}");
    let outcome: String = sqlx::query_scalar(
        "SELECT outcome FROM audit_calls WHERE request_id = $1 AND tool = 'run_query'",
    )
    .bind(&victim)
    .fetch_one(&fx.gw.state_db)
    .await
    .expect("victim row");
    assert_eq!(outcome, "cancelled");
}
