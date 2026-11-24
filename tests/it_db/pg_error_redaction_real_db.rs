//! What a Postgres error may say, over HTTP: the response body and the audit
//! row keep the SQLSTATE and the gateway's own wording, plus the name the
//! parser pointed at in the statement — never a value read from a row, not
//! even one the statement also spells. And a refused login says nothing at
//! all.
//! Target: `target-db` (`bin/dev up`).

use std::time::Duration;

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password};
use db_mcp_gateway::exec::{DbAdapter, ExecError, PgAdapter, PoolSizing};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::{config_yaml, database, owner_url, server};

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
  - group: engineers
    grants:
      - server: target
        database: app
        action: query_read
"#;

/// One row whose text value is a valid identifier (so every `reg*` cast
/// gets as far as the catalog lookup) and whose bytes are not UTF-8, plus a
/// function that raises with the value unquoted.
struct Fixture {
    owner: PgPool,
    table: String,
    raise: String,
    secret: String,
}

async fn owner() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

impl Fixture {
    async fn create() -> Self {
        let owner = owner().await;
        let id = Uuid::new_v4().simple().to_string();
        let fixture = Self {
            owner,
            table: format!("dbmcp_red_{id}"),
            raise: format!("dbmcp_red_raise_{id}"),
            secret: format!("leak_{}", Uuid::new_v4().simple()),
        };
        let (table, raise, secret) = (&fixture.table, &fixture.raise, &fixture.secret);
        for sql in [
            format!("CREATE TABLE {table} (v text NOT NULL, b bytea NOT NULL)"),
            format!("INSERT INTO {table} VALUES ('{secret}', '\\xe9616c')"),
            format!(
                "CREATE FUNCTION {raise}(v text) RETURNS int LANGUAGE plpgsql AS \
                 $$ BEGIN RAISE EXCEPTION 'refusing row %', v; END $$"
            ),
        ] {
            sqlx::query(&sql)
                .execute(&fixture.owner)
                .await
                .unwrap_or_else(|err| panic!("fixture `{sql}`: {err}"));
        }
        fixture
    }

    async fn drop(self) {
        for sql in [
            format!("DROP FUNCTION {}(text)", self.raise),
            format!("DROP TABLE {}", self.table),
        ] {
            sqlx::query(&sql)
                .execute(&self.owner)
                .await
                .expect("drop fixture");
        }
    }
}

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("test-user-{}", Uuid::new_v4().simple()),
        email: "redaction-e2e@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&config_yaml(YAML), user).await
}

/// The error body of a `run_query` the target refuses.
async fn refused(gateway: &LoggedInGateway, sql: &str) -> Value {
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client builds")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
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
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    assert_eq!(response["result"]["isError"], true, "{sql:?}: {response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("error payload is text content");
    serde_json::from_str(text).expect("error payload is JSON")
}

/// Run `sql`, expect the target to refuse it with `sqlstate`, and return
/// what the agent was told and what the audit row kept.
async fn body_and_audit(gateway: &LoggedInGateway, sql: &str, sqlstate: &str) -> (String, String) {
    let body = refused(gateway, sql).await;
    let row = latest_audit(&gateway.state_db, &gateway.user_sub, "run_query", sql).await;
    assert_eq!(
        body["request_id"].as_str(),
        Some(row.request_id.as_str()),
        "{sql:?}: the audit row is this request's"
    );
    assert_eq!(body["code"].as_str(), Some(row.outcome.as_str()), "{sql:?}");
    let message = body["message"].as_str().unwrap_or_default().to_string();
    let audited = row.error_message.unwrap_or_default();
    for text in [&message, &audited] {
        assert!(text.contains(sqlstate), "{sql:?} wants {sqlstate}: {text}");
    }
    (body.to_string(), audited)
}

/// `(expression over the row, SQLSTATE)`: each makes Postgres put the row's
/// value — or, for the encoding error, its bytes — in the primary message.
const LEAKY: &[(&str, &str)] = &[
    ("v::regclass", "42P01"),
    ("v::regtype", "42704"),
    ("v::regrole", "42704"),
    ("v::regproc", "42883"),
    ("v::regnamespace", "3F000"),
    ("to_tsquery(v || ' &')", "42601"),
    ("current_setting(v)", "42704"),
    ("v::int", "22P02"),
    ("convert_from(b, 'UTF8')", "22021"),
    ("{raise}(v)", "P0001"),
];

/// Each expression runs twice: as is, and with the row's value spelled in
/// the statement as an alias. Naming the server's words that the statement
/// also spells would confirm to the caller that a row holds that word.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_target_error_never_carries_a_row_value() {
    let fixture = Fixture::create().await;
    let gateway = boot().await;
    let mut leaks = Vec::new();
    for (expression, sqlstate) in LEAKY {
        let expression = expression.replace("{raise}", &fixture.raise);
        for alias in ["v", &fixture.secret] {
            let sql = format!("SELECT {expression} AS {alias} FROM {}", fixture.table);
            let (body, audited) = body_and_audit(&gateway, &sql, sqlstate).await;
            for (place, text) in [("response", &body), ("audit row", &audited)] {
                // `0xe9` is how Postgres prints the first byte of `b`.
                if text.contains(&fixture.secret) || text.contains("0xe9") {
                    leaks.push(format!("{place} of `{sql}`: {text}"));
                }
            }
        }
    }
    fixture.drop().await;
    assert!(leaks.is_empty(), "row data left the target:\n{leaks:#?}");
}

/// The redaction must not cost the agent the one thing it can fix: a name
/// it typed wrong is still named — as it typed it, not as the server folded
/// it — in the response and in the audit row.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_name_the_caller_typed_is_still_named() {
    let gateway = boot().await;
    for (sql, sqlstate, name) in [
        (
            "SELECT * FROM dbmcp_no_such_table",
            "42P01",
            "dbmcp_no_such_table",
        ),
        (
            "SELECT dbmcp_no_such_column FROM pg_class",
            "42703",
            "dbmcp_no_such_column",
        ),
        (
            "SELECT dbmcp_no_such_function(1)",
            "42883",
            "dbmcp_no_such_function",
        ),
        (
            "SELECT * FROM dbmcp_no_such_schema.t",
            "42P01",
            "dbmcp_no_such_schema.t",
        ),
        (
            "SELECT * FROM Dbmcp_No_Such_Table",
            "42P01",
            ": Dbmcp_No_Such_Table",
        ),
        (
            r#"SELECT * FROM "Dbmcp No Such Table""#,
            "42P01",
            "Dbmcp No Such Table",
        ),
    ] {
        let (body, audited) = body_and_audit(&gateway, sql, sqlstate).await;
        assert!(body.contains(name), "{sql:?}: {body}");
        assert!(audited.contains(name), "{sql:?}: {audited}");
    }
}

/// Postgres names the role (and, from `pg_hba`, the client address) in a
/// refused login. `cancel_query` opens its own connection, so that refusal
/// can arrive there: it must surface as an opaque connection failure and
/// retire the adapter, exactly as on the query path.
#[tokio::test]
#[serial_test::serial(world)]
async fn a_cancel_refused_at_login_carries_no_server_text() {
    let owner = owner().await;
    let role = format!("dbmcp_rot_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'first-dev-only'"
    ))
    .execute(&owner)
    .await
    .expect("create role");
    let rotated = Database {
        role: role.clone(),
        password: Password::Literal("first-dev-only".into()),
        ..database()
    };
    let a = PgAdapter::open(
        &server(),
        &rotated,
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("opens with the first password");
    sqlx::query(&format!("ALTER ROLE {role} PASSWORD 'second-dev-only'"))
        .execute(&owner)
        .await
        .expect("rotate");

    let outcome = a.cancel_request(Uuid::new_v4()).await;
    let stale = a.is_stale();
    drop(a);
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&owner)
        .await
        .expect("drop role");

    let err = outcome.expect_err("the cancel pool cannot log in");
    assert!(matches!(err, ExecError::Connection), "{err:?}");
    assert!(!format!("{err} {err:?}").contains(&role));
    assert!(stale, "a refused login retires the adapter");
}
