//! Who a Postgres error is about, over HTTP (#406). A pooler between the
//! gateway and the target answers for a target it cannot reach with an error
//! of its own, which says nothing of the caller's SQL: `unavailable`, its
//! text dropped. The very same SQLSTATE raised by the statement is the
//! statement's error. Two things tell them apart on the wire: `FATAL` ends
//! a session and never judges a statement, and Postgres puts a source
//! location in every error, a pooler none.
//! Target: `target-db` (`bin/dev up`), behind a relay that answers one
//! message in its place with the bytes the pooler sends.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use sqlx::postgres::{PgDatabaseError, PgPool, PgPoolOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::pg_unnamed_statements_real_db::{Frames, connect_target, message};
use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mcp::call_tool;
use crate::common::pg_target::{
    PORT_PLACEHOLDER, TARGET_HOST, ensure_read_role, owner_url, target_port,
};

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
  - group: engineers
    grants:
      - { server: target, database: app, action: query_write }
"#;

/// In the pooler's own text, and never in an answer or an audit row.
const POOLER_TEXT: &str = "10.11.12.13:6432 pooler_user_x";

async fn boot(port: u16) -> LoggedInGateway {
    ensure_read_role().await;
    let user = MockUser {
        sub: format!("pooler-{}", Uuid::new_v4().simple()),
        email: "pooler-e2e@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&YAML.replace(PORT_PLACEHOLDER, &port.to_string()), user).await
}

/// `run_query` of `sql`: the body of its result, and its audit row's
/// outcome and message.
async fn run_query(gw: &LoggedInGateway, sql: &str, more: Value) -> (Value, String, String) {
    let mut arguments = json!({ "server": "target", "database": "app", "sql": sql });
    for (key, value) in more.as_object().expect("more arguments") {
        arguments[key] = value.clone();
    }
    let response = call_tool(gw, "run_query", arguments).await;
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{sql}: {response}"));
    let body: Value = serde_json::from_str(text).expect("JSON payload");
    // A success body names no request; the caller has one call at a time.
    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", sql).await;
    if let Some(request_id) = body["request_id"].as_str() {
        assert_eq!(request_id, row.request_id, "{sql}: not this call's row");
    }
    (
        body,
        row.outcome.as_str().to_string(),
        row.error_message.unwrap_or_default(),
    )
}

/// A pooler's ErrorResponse: severity, SQLSTATE and text, nothing more.
/// PgBouncer sends no `V`, pgcat does.
fn pooler_error(severity: &str, v: bool, sqlstate: &str) -> Vec<u8> {
    let mut body = format!("S{severity}\0");
    if v {
        body.push_str(&format!("V{severity}\0"));
    }
    body.push_str(&format!("C{sqlstate}\0M{POOLER_TEXT}\0\0"));
    message(b'E', body.as_bytes())
}

/// One answer the relay gives in the target's place.
#[derive(Clone)]
struct Refusal {
    /// The query or Parse it answers is the next one holding this.
    to: &'static str,
    error: Vec<u8>,
    /// The transaction state reported behind it.
    state: &'static [u8],
}

/// A TCP forwarder to the target that gives the armed [`Refusal`] once.
struct Pooler {
    port: u16,
    armed: Arc<Mutex<Option<Refusal>>>,
}

impl Pooler {
    async fn start() -> Self {
        let listener = TcpListener::bind((TARGET_HOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let armed: Arc<Mutex<Option<Refusal>>> = Arc::default();
        let arm = armed.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(Self::serve(client, arm.clone()));
            }
        });
        Self { port, armed }
    }

    fn arm(&self, refusal: Refusal) {
        *self.armed.lock().unwrap() = Some(refusal);
    }

    fn fired(&self) -> bool {
        self.armed.lock().unwrap().is_none()
    }

    /// The driver reads a batch's whole answer before it sends the next, so
    /// the target has nothing in flight when the refused message arrives.
    async fn serve(mut client: TcpStream, armed: Arc<Mutex<Option<Refusal>>>) {
        let mut server = connect_target(&client).await;
        let (mut from_client, mut from_server) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut frames = Frames::from_client();
        // A refused Parse takes the rest of its batch, up to the Sync, along.
        let mut refusing: Option<Refusal> = None;
        loop {
            tokio::select! {
                read = client.read(&mut from_client) => {
                    let Ok(n @ 1..) = read else { return };
                    for frame in frames.feed(&from_client[..n]) {
                        if refusing.is_none() && matches!(frame.kind, Some(b'Q' | b'P')) {
                            let text = String::from_utf8_lossy(frame.body());
                            let mut armed = armed.lock().unwrap();
                            if armed.as_ref().is_some_and(|armed| text.contains(armed.to)) {
                                refusing = armed.take();
                            }
                        }
                        let Some(refusal) = &refusing else {
                            if server.write_all(&frame.raw).await.is_err() {
                                return;
                            }
                            continue;
                        };
                        if matches!(frame.kind, Some(b'Q' | b'S')) {
                            let answer =
                                [refusal.error.clone(), message(b'Z', refusal.state)].concat();
                            refusing = None;
                            if client.write_all(&answer).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                read = server.read(&mut from_server) => {
                    let Ok(n @ 1..) = read else { return };
                    if client.write_all(&from_server[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// pgcat's answer for every failure of its own, and PgBouncer's, wherever in
/// a call they come: the target is the problem, not the SQL.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_poolers_own_error_is_unavailable() {
    let pooler = Pooler::start().await;
    let gw = boot(pooler.port).await;
    let sql = "SELECT 41 + 1 AS answer";
    let (body, outcome, _) = run_query(&gw, sql, json!({})).await;
    assert_eq!(outcome, "success", "{body}");

    let pgcat = pooler_error("FATAL", true, "58000");
    let bouncer = pooler_error("FATAL", false, "08P01");
    // What the server told PgBouncer when it could not log in there.
    let relayed = pooler_error("FATAL", false, "3D000");
    // Odyssey's, at the severity of a statement's error.
    let odyssey = pooler_error("ERROR", true, "58000");
    for (to, error, state) in [
        ("BEGIN", &pgcat, &b"I"[..]),
        ("BEGIN", &bouncer, b"I"),
        ("BEGIN", &relayed, b"I"),
        ("BEGIN", &odyssey, b"I"),
        ("SET TRANSACTION", &pgcat, b"T"),
        (sql, &pgcat, b"T"),
        (sql, &bouncer, b"T"),
        ("COMMIT", &pgcat, b"T"),
    ] {
        let label = format!("{to}: {}", String::from_utf8_lossy(error));
        pooler.arm(Refusal {
            to,
            error: error.clone(),
            state,
        });
        let (body, outcome, audited) = run_query(&gw, sql, json!({})).await;
        assert!(pooler.fired(), "{label}: never sent");
        assert_eq!(body["code"], "unavailable", "{label}: {body}");
        assert_eq!(body["retryable"], true, "{label}: {body}");
        assert_eq!(outcome, "unavailable", "{label}");
        for text in [body.to_string(), audited] {
            assert!(!text.contains("pooler_user_x"), "{label}: {text}");
            assert!(!text.contains("10.11.12.13"), "{label}: {text}");
        }
    }
    let (body, outcome, _) = run_query(&gw, sql, json!({})).await;
    assert_eq!(outcome, "success", "once the target is back: {body}");
}

/// A write whose `COMMIT` the pooler answered may have landed: never a plain
/// refusal, which would say it did not.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_commit_the_pooler_answered_is_unknown() {
    let pooler = Pooler::start().await;
    let gw = boot(pooler.port).await;
    let table = format!("dbmcp_pooler_{}", Uuid::new_v4().simple());
    let owner = owner().await;
    run(&owner, format!("CREATE TABLE {table} (x int)")).await;
    let sql = format!("UPDATE {table} SET x = 1");
    for (severity, v, sqlstate) in [("FATAL", true, "58000"), ("FATAL", false, "08P01")] {
        pooler.arm(Refusal {
            to: "COMMIT",
            error: pooler_error(severity, v, sqlstate),
            state: b"T",
        });
        let (body, outcome, _) = run_query(&gw, &sql, json!({})).await;
        assert!(pooler.fired(), "{sqlstate}: never sent");
        assert_eq!(body["code"], "unavailable", "{sqlstate}: {body}");
        assert_eq!(body["write"], "unknown", "{sqlstate}: {body}");
        assert_eq!(body["retryable"], false, "{sqlstate}: {body}");
        assert_eq!(outcome, "unavailable", "{sqlstate}");
    }
    run(&owner, format!("DROP TABLE {table}")).await;
}

/// The statement's own error keeps its SQLSTATE, whatever the code: a
/// function can raise any, and a placeholder without a param is refused as
/// `08P01`. No text of it passes. Class `08` but for that code stays what a
/// remote server out of reach (`dblink`, a foreign table) is: retryable.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_same_sqlstate_raised_by_the_statement_is_not_unavailable() {
    let owner = owner().await;
    let name = format!("dbmcp_raise_{}", Uuid::new_v4().simple());
    run(
        &owner,
        format!(
            "CREATE FUNCTION {name}(code text) RETURNS int LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION '{POOLER_TEXT}' USING ERRCODE = code, HINT = '{POOLER_TEXT}'; \
             END $$"
        ),
    )
    .await;
    let raw = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SELECT {name}('58000')")))
        .execute(&owner)
        .await
        .expect_err("raises");
    let raw = raw.as_database_error().expect("server error");
    let raw = raw.downcast_ref::<PgDatabaseError>();
    assert!(raw.file().is_some() || raw.routine().is_some(), "{raw:?}");

    let gw = boot(target_port()).await;
    let mut answers = Vec::new();
    for sqlstate in ["58000", "58030", "58P01", "08P01", "08006"] {
        let sql = format!("SELECT {name}('{sqlstate}')");
        answers.push((sqlstate, run_query(&gw, &sql, json!({})).await));
    }
    let unbound = run_query(&gw, "SELECT $1::int + $2::int", json!({ "params": [1] })).await;
    answers.push(("08P01", unbound));
    run(&owner, format!("DROP FUNCTION {name}(text)")).await;

    for (sqlstate, (body, outcome, audited)) in answers {
        for text in [body.to_string(), audited.clone()] {
            assert!(!text.contains("pooler_user_x"), "{sqlstate}: {text}");
        }
        if sqlstate == "08006" {
            assert_eq!(body["code"], "unavailable", "{sqlstate}: {body}");
            assert_eq!(outcome, "unavailable", "{sqlstate}");
            continue;
        }
        assert_eq!(body["code"], "syntax_error", "{sqlstate}: {body}");
        assert_eq!(body["retryable"], false, "{sqlstate}: {body}");
        assert_eq!(outcome, "syntax_error", "{sqlstate}");
        assert!(audited.contains(sqlstate), "{sqlstate}: {audited}");
        let told = body["message"].as_str().expect("message");
        assert!(told.contains(sqlstate), "{sqlstate}: {body}");
    }
}

async fn owner() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

async fn run(owner: &PgPool, sql: String) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone()))
        .execute(owner)
        .await
        .unwrap_or_else(|err| panic!("{sql}: {err}"));
}
