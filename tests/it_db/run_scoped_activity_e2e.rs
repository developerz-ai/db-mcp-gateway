//! Run-scoped `db_activity` / `cancel_query` for service tokens (#398,
//! spec 14 §Upstream attribution): two runs of one service account each see
//! and cancel only their own statement; another run's request id answers
//! exactly like an unknown one; a call without `x-dbmcp-run-id` keeps the
//! account-wide view; an SSO session's run header is ignored.
//!
//! Needs the target Postgres (`bin/dev up`).

use std::sync::Arc;
use std::time::Duration;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

const TOKEN: &str = "dbmcp_svc_6666666666666666666666666666666666666666666666666666666666666666";
const RUN_A: &str = "run-a";
const RUN_B: &str = "run-b";
const SLOW_SQL: &str = "SELECT pg_sleep(20)";

fn yaml(account: &str) -> String {
    let port = crate::common::pg_target::target_port();
    format!(
        r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: {port}
    tls: insecure
    databases:
      - {{ name: app, role: app, password: app-dev-only }}

permissions:
  - group: inspectors
    grants:
      - {{ server: target, database: app, action: query_read }}
  - group: fleet
    grants:
      - {{ server: target, database: app, action: query_read }}

service_accounts:
  - name: {account}
    group: fleet
    token: {TOKEN}
"#
    )
}

struct Fixture {
    gw: LoggedInGateway,
    account: String,
}

impl Fixture {
    async fn new() -> Self {
        let account = format!("fleet-{}", uuid::Uuid::new_v4().simple());
        let user = MockUser {
            sub: format!("inspector-{}", uuid::Uuid::new_v4().simple()),
            email: "inspector@example.com".into(),
            groups: vec!["inspectors".into()],
        };
        let gw = spawn_logged_in(&yaml(&account), user).await;
        Self { gw, account }
    }

    fn service_sub(&self) -> String {
        format!("service:{}", self.account)
    }

    /// One tool call as `bearer`, with `run` (if any) as `x-dbmcp-run-id`.
    async fn call(&self, bearer: &str, run: Option<&str>, tool: &str, args: Value) -> Value {
        let mut arguments = json!({ "server": "target", "database": "app" });
        for (key, value) in args.as_object().expect("object") {
            arguments[key] = value.clone();
        }
        let mut request = reqwest::Client::new()
            .post(format!("{}/mcp", self.gw.url))
            .bearer_auth(bearer)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            }));
        if let Some(run) = run {
            request = request.header("x-dbmcp-run-id", run);
        }
        request.send().await.unwrap().json().await.unwrap()
    }

    /// The request id of `user_sub`'s in-flight `run_query` under `run`
    /// (`None` = no run claimed), from its intent row.
    async fn running_request_id(&self, user_sub: &str, run: Option<&str>) -> String {
        for _ in 0..50 {
            let found: Option<String> = sqlx::query_scalar(
                "SELECT request_id FROM audit_call_intents \
                 WHERE user_sub = $1 AND tool = 'run_query' \
                   AND upstream_run_id IS NOT DISTINCT FROM $2 \
                 ORDER BY occurred_at DESC LIMIT 1",
            )
            .bind(user_sub)
            .bind(run)
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

    /// The outcome and claimed run of the completion row for `request_id`.
    async fn row_of(&self, request_id: &str) -> (String, Option<String>) {
        sqlx::query_as("SELECT outcome, upstream_run_id FROM audit_calls WHERE request_id = $1")
            .bind(request_id)
            .fetch_one(&self.gw.state_db)
            .await
            .expect("completion row")
    }
}

fn slow_query(fx: &Arc<Fixture>, bearer: String, run: Option<&'static str>) -> JoinHandle<Value> {
    let fx = fx.clone();
    tokio::spawn(async move {
        fx.call(&bearer, run, "run_query", json!({ "sql": SLOW_SQL }))
            .await
    })
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text content: {response}"));
    serde_json::from_str(text).expect("payload is valid JSON")
}

async fn finished(slow: JoinHandle<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(10), slow)
        .await
        .expect("cancelled query returns promptly")
        .expect("task")
}

/// Each run lists only its own statement and can cancel only it; another
/// run's id is refused with the unknown-id answer, byte for byte.
#[tokio::test]
#[serial_test::parallel(world)]
async fn each_run_sees_and_cancels_only_its_own_statement() {
    let fx = Arc::new(Fixture::new().await);
    let subject = fx.service_sub();
    let slow_a = slow_query(&fx, TOKEN.into(), Some(RUN_A));
    let slow_b = slow_query(&fx, TOKEN.into(), Some(RUN_B));
    let id_a = fx.running_request_id(&subject, Some(RUN_A)).await;
    let id_b = fx.running_request_id(&subject, Some(RUN_B)).await;

    let seen_a = payload(&fx.call(TOKEN, Some(RUN_A), "db_activity", json!({})).await);
    assert!(
        seen_a.to_string().contains(&id_a),
        "run A sees its own: {seen_a}"
    );
    assert!(
        !seen_a.to_string().contains(&id_b),
        "run A must not see B: {seen_a}"
    );
    let row = latest_audit(&fx.gw.state_db, &subject, "db_activity", "run A activity").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.upstream_run_id.as_deref(), Some(RUN_A));

    let seen_b = payload(&fx.call(TOKEN, Some(RUN_B), "db_activity", json!({})).await);
    assert!(
        seen_b.to_string().contains(&id_b),
        "run B sees its own: {seen_b}"
    );
    assert!(
        !seen_b.to_string().contains(&id_a),
        "run B must not see A: {seen_b}"
    );

    // Without the header the account-wide view is unchanged.
    let seen_all = payload(&fx.call(TOKEN, None, "db_activity", json!({})).await);
    assert!(
        seen_all.to_string().contains(&id_a) && seen_all.to_string().contains(&id_b),
        "no run header: today's view: {seen_all}"
    );

    let cross = fx
        .call(
            TOKEN,
            Some(RUN_A),
            "cancel_query",
            json!({ "request_id": id_b }),
        )
        .await;
    let cross_body = payload(&cross);
    assert_eq!(cross_body["code"], "forbidden", "{cross}");
    let row = latest_audit(&fx.gw.state_db, &subject, "cancel_query", "cross-run").await;
    assert_eq!(row.outcome, "forbidden");
    assert_eq!(row.upstream_run_id.as_deref(), Some(RUN_A));
    assert_eq!(row.sql.as_deref(), Some(id_b.as_str()));

    let unknown = uuid::Uuid::new_v4().to_string();
    let unknown_resp = fx
        .call(
            TOKEN,
            Some(RUN_A),
            "cancel_query",
            json!({ "request_id": unknown }),
        )
        .await;
    let unknown_body = payload(&unknown_resp);
    assert_eq!(unknown_body["code"], "forbidden", "{unknown_resp}");
    assert_eq!(
        cross_body["message"], unknown_body["message"],
        "another run's id must answer like an unknown one"
    );
    let row = latest_audit(&fx.gw.state_db, &subject, "cancel_query", "unknown id").await;
    assert_eq!(row.outcome, "forbidden");
    assert_eq!(row.sql.as_deref(), Some(unknown.as_str()));

    for (run, victim, slow) in [(RUN_A, &id_a, slow_a), (RUN_B, &id_b, slow_b)] {
        let resp = fx
            .call(
                TOKEN,
                Some(run),
                "cancel_query",
                json!({ "request_id": victim }),
            )
            .await;
        assert_eq!(payload(&resp)["cancelled"], true, "{run}: {resp}");
        let row = latest_audit(&fx.gw.state_db, &subject, "cancel_query", run).await;
        assert_eq!(row.outcome, "success");
        assert_eq!(row.upstream_run_id.as_deref(), Some(run));

        let victim_resp = finished(slow).await;
        assert_eq!(payload(&victim_resp)["code"], "cancelled", "{victim_resp}");
        assert_eq!(
            fx.row_of(victim).await,
            ("cancelled".to_string(), Some(run.to_string()))
        );
    }
}

/// An SSO session's run header is ignored: it still sees and cancels its
/// own statement.
#[tokio::test]
#[serial_test::parallel(world)]
async fn sso_session_is_not_run_scoped() {
    let fx = Arc::new(Fixture::new().await);
    let user_sub = fx.gw.user_sub.clone();
    let slow = slow_query(&fx, fx.gw.bearer.clone(), None);
    let victim = fx.running_request_id(&user_sub, None).await;

    let seen = payload(
        &fx.call(&fx.gw.bearer, Some(RUN_A), "db_activity", json!({}))
            .await,
    );
    assert!(seen.to_string().contains(&victim), "{seen}");
    let row = latest_audit(&fx.gw.state_db, &user_sub, "db_activity", "sso activity").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.upstream_run_id, None);

    let resp = fx
        .call(
            &fx.gw.bearer,
            Some(RUN_A),
            "cancel_query",
            json!({ "request_id": victim }),
        )
        .await;
    assert_eq!(payload(&resp)["cancelled"], true, "{resp}");
    let row = latest_audit(&fx.gw.state_db, &user_sub, "cancel_query", "sso cancel").await;
    assert_eq!(row.outcome, "success");

    let victim_resp = finished(slow).await;
    assert_eq!(payload(&victim_resp)["code"], "cancelled", "{victim_resp}");
    assert_eq!(fx.row_of(&victim).await, ("cancelled".to_string(), None));
}
