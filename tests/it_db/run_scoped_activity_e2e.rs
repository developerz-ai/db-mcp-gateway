//! Run-scoped `db_activity` / `cancel_query` for service tokens (#398,
//! spec 14 §Upstream attribution): two runs of one service account each see
//! and cancel only their own statement; another run's request id answers
//! exactly like an unknown one; a call without `x-dbmcp-run-id` keeps the
//! account-wide view; an SSO session's run header is ignored. `run_scoped:
//! true` refuses every call that would not be narrowed to a run, before the
//! target or any lookup.
//!
//! Needs the target Postgres (`bin/dev up`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use db_mcp_gateway::audit::AuditRow;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

const TOKEN: &str = "dbmcp_svc_6666666666666666666666666666666666666666666666666666666666666666";
const STRICT_TOKEN: &str =
    "dbmcp_svc_7777777777777777777777777777777777777777777777777777777777777777";
const RUN_HEADER: &str = "x-dbmcp-run-id";
const ACTOR_HEADER: &str = "x-dbmcp-on-behalf-of";
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
  - name: dead
    kind: postgres
    description: nothing listens here, so a target call answers `unavailable`
    host: 127.0.0.1
    port: 1
    tls: insecure
    databases:
      - {{ name: app, role: app, password: app-dev-only }}

permissions:
  - group: inspectors
    grants:
      - {{ server: target, database: app, action: query_read }}
      - {{ server: dead, database: app, action: query_read }}
  - group: fleet
    grants:
      - {{ server: target, database: app, action: query_read }}
      - {{ server: dead, database: app, action: query_read }}

service_accounts:
  - name: {account}
    group: fleet
    token: {TOKEN}
  - name: {account}-strict
    group: fleet
    token: {STRICT_TOKEN}
    require_upstream: true
"#
    )
}

type Headers<'a> = &'a [(&'a str, &'a str)];

/// Who calls, and the attribution headers they send.
struct Caller<'a> {
    bearer: &'a str,
    sub: &'a str,
    headers: Headers<'a>,
}

struct Fixture {
    gw: LoggedInGateway,
    account: String,
    target: sqlx::PgPool,
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
        let target = sqlx::PgPool::connect(&crate::common::env::target_db_url())
            .await
            .expect("target db reachable");
        Self {
            gw,
            account,
            target,
        }
    }

    fn service_sub(&self) -> String {
        format!("service:{}", self.account)
    }

    /// One tool call as `bearer`, with `run` (if any) as `x-dbmcp-run-id`.
    async fn call(&self, bearer: &str, run: Option<&str>, tool: &str, args: Value) -> Value {
        let headers: Vec<_> = run.map(|run| (RUN_HEADER, run)).into_iter().collect();
        self.call_with(bearer, &headers, tool, args).await
    }

    async fn call_with(
        &self,
        bearer: &str,
        headers: Headers<'_>,
        tool: &str,
        args: Value,
    ) -> Value {
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
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.send().await.unwrap().json().await.unwrap()
    }

    /// The request id of `user_sub`'s in-flight `run_query` under `run`
    /// (`None` = no run claimed), once its statement is active on the target:
    /// the intent row commits before the pool opens.
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
            if let Some(id) = found
                && self.active_on_target(&id).await
            {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the slow query never ran on the target");
    }

    /// Whether a target backend tagged with `request_id` is running
    /// [`SLOW_SQL`].
    async fn active_on_target(&self, request_id: &str) -> bool {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM pg_stat_activity \
             WHERE state = 'active' AND query = $1 \
               AND starts_with(application_name, 'dbmcp-' || replace($2, '-', '')))",
        )
        .bind(SLOW_SQL)
        .bind(request_id)
        .fetch_one(&self.target)
        .await
        .unwrap()
    }

    /// `user_sub`'s audit rows for `tool`.
    async fn audit_rows(&self, user_sub: &str, tool: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_calls WHERE user_sub = $1 AND tool = $2")
            .bind(user_sub)
            .bind(tool)
            .fetch_one(&self.gw.state_db)
            .await
            .unwrap()
    }

    /// `user_sub`'s intent rows for `tool`: one commits before any target
    /// call and stays, so an unchanged count means the target was not called.
    async fn intents(&self, user_sub: &str, tool: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM audit_call_intents WHERE user_sub = $1 AND tool = $2",
        )
        .bind(user_sub)
        .bind(tool)
        .fetch_one(&self.gw.state_db)
        .await
        .unwrap()
    }

    /// Make the call and assert it is refused `invalid_arguments` with one
    /// audit row and no target call. Returns the message and the row.
    async fn refused(
        &self,
        caller: &Caller<'_>,
        tool: &str,
        args: Value,
        label: &str,
    ) -> (String, AuditRow) {
        let rows = self.audit_rows(caller.sub, tool).await;
        let intents = self.intents(caller.sub, tool).await;
        let resp = self
            .call_with(caller.bearer, caller.headers, tool, args)
            .await;
        assert_eq!(resp["error"]["code"], -32602, "{label}: {resp}");
        assert!(resp.get("result").is_none(), "{label}: {resp}");
        let row = latest_audit(&self.gw.state_db, caller.sub, tool, label).await;
        assert_eq!(row.outcome, "invalid_arguments", "{label}");
        assert_eq!(row.elapsed_ms, None, "{label}: no target call was timed");
        assert_eq!(
            self.audit_rows(caller.sub, tool).await,
            rows + 1,
            "{label}: exactly one audit row"
        );
        assert_eq!(
            self.intents(caller.sub, tool).await,
            intents,
            "{label}: the target was never in play"
        );
        let message = resp["error"]["message"].as_str().unwrap_or_default();
        (message.to_owned(), row)
    }

    /// The `request_id`s `db_activity` lists for this call.
    async fn listed(&self, caller: &Caller<'_>, args: Value) -> HashSet<String> {
        let resp = self
            .call_with(caller.bearer, caller.headers, "db_activity", args)
            .await;
        let body = payload(&resp);
        let column = body["columns"]
            .as_array()
            .expect("columns")
            .iter()
            .position(|c| c == "request_id")
            .expect("request_id column");
        body["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .filter_map(|row| row[column].as_str().map(str::to_owned))
            .collect()
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

/// `run_scoped: true` with a run id answers for that run only, and another
/// run's statement still answers exactly like an unknown one.
#[tokio::test]
#[serial_test::parallel(world)]
async fn run_scoped_true_with_a_run_covers_only_that_run() {
    let fx = Arc::new(Fixture::new().await);
    let subject = fx.service_sub();
    let slow_a = slow_query(&fx, TOKEN.into(), Some(RUN_A));
    let slow_b = slow_query(&fx, TOKEN.into(), Some(RUN_B));
    let id_a = fx.running_request_id(&subject, Some(RUN_A)).await;
    let id_b = fx.running_request_id(&subject, Some(RUN_B)).await;
    let caller = Caller {
        bearer: TOKEN,
        sub: &subject,
        headers: &[(RUN_HEADER, RUN_A)],
    };

    let seen = fx.listed(&caller, json!({ "run_scoped": true })).await;
    assert!(seen.contains(&id_a) && !seen.contains(&id_b), "{seen:?}");
    let row = latest_audit(&fx.gw.state_db, &subject, "db_activity", "scoped activity").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.upstream_run_id.as_deref(), Some(RUN_A));

    let mut messages = Vec::new();
    for victim in [id_b.clone(), uuid::Uuid::new_v4().to_string()] {
        let resp = fx
            .call(
                TOKEN,
                Some(RUN_A),
                "cancel_query",
                json!({ "request_id": victim, "run_scoped": true }),
            )
            .await;
        let body = payload(&resp);
        assert_eq!(body["code"], "forbidden", "{resp}");
        messages.push(body["message"].clone());
        let row = latest_audit(&fx.gw.state_db, &subject, "cancel_query", "not own").await;
        assert_eq!(row.outcome, "forbidden");
        assert_eq!(row.sql.as_deref(), Some(victim.as_str()));
    }
    assert_eq!(
        messages[0], messages[1],
        "another run's id reads as unknown"
    );
    assert!(fx.active_on_target(&id_b).await, "run B still runs");

    for (run, victim, slow) in [(RUN_A, &id_a, slow_a), (RUN_B, &id_b, slow_b)] {
        let resp = fx
            .call(
                TOKEN,
                Some(run),
                "cancel_query",
                json!({ "request_id": victim, "run_scoped": true }),
            )
            .await;
        assert_eq!(payload(&resp)["cancelled"], true, "{run}: {resp}");
        let row = latest_audit(&fx.gw.state_db, &subject, "cancel_query", run).await;
        assert_eq!(row.outcome, "success");
        let victim_resp = finished(slow).await;
        assert_eq!(payload(&victim_resp)["code"], "cancelled", "{victim_resp}");
    }
}

/// `run_scoped: true` is refused whenever no run narrows the call: a service
/// token without the run header (or with only the other header), an SSO
/// session whatever it sends. The refusal comes before the target, before the
/// ownership lookup and before authz — a dead or unknown server gets the same
/// answer — and cancels nothing, not even the caller's own statement.
#[tokio::test]
#[serial_test::parallel(world)]
async fn run_scoped_true_without_a_run_is_refused_before_any_lookup() {
    let fx = Arc::new(Fixture::new().await);
    let service = fx.service_sub();
    let sso = fx.gw.user_sub.clone();
    let sso_bearer = fx.gw.bearer.clone();
    let slow_service = slow_query(&fx, TOKEN.into(), None);
    let slow_sso = slow_query(&fx, sso_bearer.clone(), None);
    let service_victim = fx.running_request_id(&service, None).await;
    let sso_victim = fx.running_request_id(&sso, None).await;

    let cases: [(&str, &str, &str, Headers<'_>); 4] = [
        (TOKEN, &service, &service_victim, &[]),
        (TOKEN, &service, &service_victim, &[(ACTOR_HEADER, "ci")]),
        (&sso_bearer, &sso, &sso_victim, &[]),
        (&sso_bearer, &sso, &sso_victim, &[(RUN_HEADER, RUN_A)]),
    ];
    for (bearer, sub, victim, headers) in cases {
        let caller = Caller {
            bearer,
            sub,
            headers,
        };
        for server in ["target", "dead", "nowhere"] {
            for tool in ["db_activity", "cancel_query"] {
                let label = format!("{sub} {headers:?} {tool} on {server}");
                let mut args = json!({ "server": server, "run_scoped": true });
                if tool == "cancel_query" {
                    args["request_id"] = json!(victim);
                }
                let (message, row) = fx.refused(&caller, tool, args, &label).await;
                assert!(message.contains("`run_scoped`"), "{label}: {message}");
                assert_eq!(row.error_message.as_deref(), Some(message.as_str()));
                assert_eq!(row.server.as_deref(), Some(server), "{label}");
                assert_eq!(row.database.as_deref(), Some("app"), "{label}");
                assert_eq!(row.db_type, None, "{label}: the server is not looked up");
                assert_eq!(row.upstream_run_id, None, "{label}");
            }
        }
        assert!(
            fx.active_on_target(victim).await,
            "{sub} {headers:?}: a refused cancel must not cancel"
        );
    }

    // The control: the same calls without `run_scoped` do reach the target —
    // the victims are cancelled, and the dead server answers for itself.
    for (bearer, sub, victim, slow) in [
        (TOKEN, &service, &service_victim, slow_service),
        (sso_bearer.as_str(), &sso, &sso_victim, slow_sso),
    ] {
        let args = json!({ "request_id": victim });
        let resp = fx.call(bearer, None, "cancel_query", args).await;
        assert_eq!(payload(&resp)["cancelled"], true, "{sub}: {resp}");
        let row = latest_audit(&fx.gw.state_db, sub, "cancel_query", "control").await;
        assert_eq!(row.outcome, "success");
        finished(slow).await;
    }
    for (bearer, sub) in [(TOKEN, &service), (sso_bearer.as_str(), &sso)] {
        let intents = fx.intents(sub, "db_activity").await;
        let resp = fx
            .call(bearer, None, "db_activity", json!({ "server": "dead" }))
            .await;
        assert_eq!(payload(&resp)["code"], "unavailable", "{sub}: {resp}");
        assert_eq!(fx.intents(sub, "db_activity").await, intents + 1, "{sub}");
    }
}

/// `false` is absent: same listing, same refusal body, whoever asks.
#[tokio::test]
#[serial_test::parallel(world)]
async fn run_scoped_false_is_the_same_as_absent() {
    let fx = Arc::new(Fixture::new().await);
    let service = fx.service_sub();
    let sso = fx.gw.user_sub.clone();
    let slow_a = slow_query(&fx, TOKEN.into(), Some(RUN_A));
    let slow_b = slow_query(&fx, TOKEN.into(), Some(RUN_B));
    let slow_sso = slow_query(&fx, fx.gw.bearer.clone(), None);
    let id_a = fx.running_request_id(&service, Some(RUN_A)).await;
    let id_b = fx.running_request_id(&service, Some(RUN_B)).await;
    let id_sso = fx.running_request_id(&sso, None).await;

    // Each caller, the statements it owns, and a live one it does not:
    // another identity's, or — for run A — run B's of the same identity.
    let run_a: Headers<'_> = &[(RUN_HEADER, RUN_A)];
    let cases: [(&str, &str, Headers<'_>, &[&String], &String); 3] = [
        (TOKEN, &service, &[], &[&id_a, &id_b], &id_sso),
        (TOKEN, &service, run_a, &[&id_a], &id_b),
        (&fx.gw.bearer, &sso, run_a, &[&id_sso], &id_a),
    ];
    for (bearer, sub, headers, running, foreign) in cases {
        let caller = Caller {
            bearer,
            sub,
            headers,
        };
        let running: HashSet<String> = running.iter().map(|id| (*id).clone()).collect();
        for args in [json!({}), json!({ "run_scoped": false })] {
            let seen: HashSet<String> = fx
                .listed(&caller, args.clone())
                .await
                .into_iter()
                .filter(|id| [&id_a, &id_b, &id_sso].contains(&id))
                .collect();
            assert_eq!(seen, running, "{sub} {headers:?} {args}");
            let row = latest_audit(&fx.gw.state_db, sub, "db_activity", "false activity").await;
            assert_eq!(row.outcome, "success");
        }

        let mut bodies = Vec::new();
        for mut args in [json!({}), json!({ "run_scoped": false })] {
            args["request_id"] = json!(foreign);
            let resp = fx.call_with(bearer, headers, "cancel_query", args).await;
            let row = latest_audit(&fx.gw.state_db, sub, "cancel_query", "foreign").await;
            assert_eq!(row.outcome, "forbidden", "{sub} {headers:?}: {resp}");
            assert_eq!(row.sql.as_deref(), Some(foreign.as_str()));
            assert!(
                fx.active_on_target(foreign).await,
                "{sub} {headers:?}: a statement it does not own must keep running"
            );
            let mut body = payload(&resp);
            body["request_id"] = Value::Null;
            bodies.push(body);
        }
        assert_eq!(bodies[0]["code"], "forbidden", "{sub} {headers:?}");
        assert_eq!(bodies[0], bodies[1], "{sub} {headers:?}");
    }

    // `false` does not narrow a header-less call: it cancels either run's.
    for (bearer, sub, victim, slow) in [
        (TOKEN, &service, &id_a, slow_a),
        (TOKEN, &service, &id_b, slow_b),
        (fx.gw.bearer.as_str(), &sso, &id_sso, slow_sso),
    ] {
        let args = json!({ "request_id": victim, "run_scoped": false });
        let resp = fx.call(bearer, None, "cancel_query", args).await;
        assert_eq!(payload(&resp)["cancelled"], true, "{sub}: {resp}");
        let row = latest_audit(&fx.gw.state_db, sub, "cancel_query", "false cancel").await;
        assert_eq!(row.outcome, "success");
        finished(slow).await;
    }
}

/// Anything but a JSON boolean is refused — never read as either value — even
/// where `true` would have been answered.
#[tokio::test]
#[serial_test::parallel(world)]
async fn run_scoped_of_another_type_is_refused() {
    let fx = Arc::new(Fixture::new().await);
    let subject = fx.service_sub();
    let slow = slow_query(&fx, TOKEN.into(), Some(RUN_A));
    let victim = fx.running_request_id(&subject, Some(RUN_A)).await;
    let caller = Caller {
        bearer: TOKEN,
        sub: &subject,
        headers: &[(RUN_HEADER, RUN_A)],
    };
    for bad in [
        json!("true"),
        json!(1),
        json!(0),
        Value::Null,
        json!([true]),
        json!({}),
    ] {
        for tool in ["db_activity", "cancel_query"] {
            let label = format!("{tool} run_scoped: {bad}");
            let mut args = json!({ "run_scoped": bad });
            if tool == "cancel_query" {
                args["request_id"] = json!(victim);
            }
            let (message, row) = fx.refused(&caller, tool, args, &label).await;
            assert!(message.contains("expected a boolean"), "{label}: {message}");
            assert_eq!(row.server, None, "{label}: the arguments never parsed");
        }
    }
    assert!(fx.active_on_target(&victim).await, "nothing was cancelled");

    let args = json!({ "request_id": victim, "run_scoped": true });
    let resp = fx.call(TOKEN, Some(RUN_A), "cancel_query", args).await;
    assert_eq!(payload(&resp)["cancelled"], true, "{resp}");
    finished(slow).await;
}

/// Under `require_upstream` the account's own rule answers first: a call
/// missing either header is refused whatever `run_scoped` says, and one with
/// both is scoped, so `true` is answered.
#[tokio::test]
#[serial_test::parallel(world)]
async fn run_scoped_under_require_upstream() {
    let fx = Fixture::new().await;
    let subject = format!("{}-strict", fx.service_sub());
    let cases: [Headers<'_>; 3] = [&[], &[(RUN_HEADER, RUN_A)], &[(ACTOR_HEADER, "ci")]];
    for headers in cases {
        let caller = Caller {
            bearer: STRICT_TOKEN,
            sub: &subject,
            headers,
        };
        for args in [json!({}), json!({ "run_scoped": true })] {
            let label = format!("{headers:?} {args}");
            let (message, _) = fx.refused(&caller, "db_activity", args, &label).await;
            assert!(message.contains("requires the"), "{label}: {message}");
        }
    }

    let caller = Caller {
        bearer: STRICT_TOKEN,
        sub: &subject,
        headers: &[(RUN_HEADER, RUN_A), (ACTOR_HEADER, "ci")],
    };
    fx.listed(&caller, json!({ "run_scoped": true })).await;
    let row = latest_audit(&fx.gw.state_db, &subject, "db_activity", "strict").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.upstream_run_id.as_deref(), Some(RUN_A));
}
