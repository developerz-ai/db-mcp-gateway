//! What a refused statement tells the agent beyond its code, against
//! `target-db`: the error position, the parser's hint, and the existing
//! names closest to a typo'd table or column — only names the read role can
//! see, and nothing at all for an error raised over row data.

use std::time::Duration;

use db_mcp_gateway::exec::{
    Access, DbAdapter, DbRejection, ExecError, ExecQuery, ExplainQuery, GuardedSql,
};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::spawn_logged_in;
use crate::common::idp::MockUser;
use crate::common::pg_target::{READ_ROLE, adapter, config_yaml, owner_url, writable_adapter};

async fn owner() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

async fn exec(owner: &PgPool, sql: &str) {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(owner)
        .await
        .unwrap_or_else(|err| panic!("fixture `{sql}`: {err}"));
}

fn query(sql: &str) -> ExecQuery<'_> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 10,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    }
}

async fn rejected(adapter: &dyn DbAdapter, sql: &str) -> DbRejection {
    match adapter.execute(query(sql)).await {
        Err(ExecError::Rejected(rejection)) => rejection,
        other => panic!("{sql:?}: expected a rejection, got {other:?}"),
    }
}

/// A public table with an `email` column, named per run.
struct Table {
    owner: PgPool,
    name: String,
}

impl Table {
    async fn create() -> Self {
        let owner = owner().await;
        let name = format!("nm{}", &Uuid::new_v4().simple().to_string()[..8]);
        exec(
            &owner,
            &format!("CREATE TABLE public.{name} (id int, email text, total int)"),
        )
        .await;
        Self { owner, name }
    }

    /// The name with a `q` (never a hex digit) inserted before its last
    /// character: one edit away, and never the name itself.
    fn typo(&self) -> String {
        let (head, last) = self.name.split_at(self.name.len() - 1);
        format!("{head}q{last}")
    }

    async fn drop(self) {
        exec(&self.owner, &format!("DROP TABLE public.{}", self.name)).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_typo_gets_its_position_hint_and_near_misses() {
    let table = Table::create().await;
    let a = adapter().await;

    let sql = format!("SELECT emial FROM {}", table.name);
    let column = rejected(&a, &sql).await;
    let sql = format!("SELECT id FROM {}", table.typo());
    let relation = rejected(&a, &sql).await;
    let syntax = rejected(&a, "SELECT 1 FORM t").await;
    let name = table.name.clone();
    table.drop().await;

    assert_eq!(column.sqlstate(), "42703");
    assert_eq!(column.position(), Some(8));
    assert!(
        column.near_misses().iter().any(|n| n == "email"),
        "{column:?}"
    );
    assert!(column.near_misses().len() <= 5, "{column:?}");
    assert_eq!(column.hint(), None, "{column:?}");

    assert_eq!(relation.sqlstate(), "42P01");
    assert_eq!(relation.position(), Some(16));
    assert_eq!(relation.near_misses().first(), Some(&name), "{relation:?}");

    assert_eq!(syntax.sqlstate(), "42601");
    assert_eq!(syntax.position(), Some(15));
    assert!(syntax.near_misses().is_empty());
}

/// The parser's hint passes through — except a column diagnostic's, which
/// near misses replace.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_parser_hint_is_passed_on() {
    let table = Table::create().await;
    let a = adapter().await;
    let sql = format!("SELECT t.emial FROM {} t", table.name);
    let rejection = rejected(&a, &sql).await;
    let missing = rejected(&a, "SELECT dbmcp_no_such_fn(1)").await;
    table.drop().await;

    assert_eq!(rejection.sqlstate(), "42703");
    assert_eq!(rejection.position(), Some(8));
    assert_eq!(rejection.hint(), None, "{rejection:?}");
    assert!(
        rejection.near_misses().iter().any(|n| n == "email"),
        "{rejection:?}"
    );
    assert_eq!(missing.sqlstate(), "42883");
    assert!(
        missing
            .hint()
            .is_some_and(|hint| hint.contains("explicit type casts")),
        "{missing:?}"
    );
}

/// `explain` wraps the statement: the position still counts from the
/// caller's text.
#[tokio::test]
#[serial_test::parallel(world)]
async fn an_explain_position_counts_from_the_callers_statement() {
    let table = Table::create().await;
    let a = adapter().await;
    let sql = format!("SELECT emial FROM {}", table.name);
    let guarded = GuardedSql::parse(&sql, Access::ReadOnly)
        .await
        .expect("guarded");
    let result = a
        .explain(ExplainQuery {
            sql: guarded,
            analyze: false,
            statement_timeout_ms: None,
            request_id: Uuid::new_v4(),
        })
        .await;
    table.drop().await;
    let Err(ExecError::Rejected(rejection)) = result else {
        panic!("expected a rejection, got {result:?}");
    };
    assert_eq!(rejection.position(), Some(8));
    assert!(rejection.near_misses().iter().any(|n| n == "email"));
}

/// A name the read role cannot see is never offered — even when it is the
/// closest one there is.
#[tokio::test]
#[serial_test::serial(world)]
async fn near_misses_are_only_names_the_read_role_can_see() {
    let a = writable_adapter().await;
    let owner = owner().await;
    let hidden = format!("hid{}", &Uuid::new_v4().simple().to_string()[..8]);
    exec(&owner, &format!("CREATE SCHEMA {hidden}")).await;
    exec(
        &owner,
        &format!("CREATE TABLE {hidden}.ledger_rows (x int)"),
    )
    .await;
    let rejection = rejected(&a, "SELECT * FROM ledger_rosw").await;
    exec(&owner, &format!("DROP SCHEMA {hidden} CASCADE")).await;

    assert_eq!(rejection.sqlstate(), "42P01");
    assert!(
        !rejection
            .near_misses()
            .iter()
            .any(|n| n.contains("ledger_rows")),
        "{rejection:?}"
    );
}

/// Postgres suggests a column for a typo from the whole relation, column
/// grants aside: the server's hint for an undefined column is never passed
/// on, so a column the read role cannot see is never named.
// Parallel: the grants touch only this test's own schema and table.
#[tokio::test]
#[serial_test::parallel(world)]
async fn an_undefined_column_hint_never_names_a_hidden_column() {
    let a = writable_adapter().await;
    let owner = owner().await;
    let schema = format!("hcol{}", &Uuid::new_v4().simple().to_string()[..8]);
    for sql in [
        format!("CREATE SCHEMA {schema}"),
        format!("CREATE TABLE {schema}.payroll (id int, salary_band text)"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {READ_ROLE}"),
        format!("GRANT SELECT (id) ON {schema}.payroll TO {READ_ROLE}"),
    ] {
        exec(&owner, &sql).await;
    }
    let sql = format!("SELECT t.salary_bnad FROM {schema}.payroll t");
    let rejection = rejected(&a, &sql).await;
    exec(&owner, &format!("DROP SCHEMA {schema} CASCADE")).await;

    assert_eq!(rejection.sqlstate(), "42703");
    let told = format!("{:?}", (rejection.hint(), rejection.near_misses()));
    assert!(!told.contains("salary_band"), "{rejection:?}");
}

/// Raised over row data: a row holds a name one edit from a real table, and
/// casting it to `regclass` fails at run time — no position, so no hint and
/// no lookup that could confirm what the row holds.
#[tokio::test]
#[serial_test::parallel(world)]
async fn an_error_over_row_data_gets_no_hint_and_no_near_misses() {
    let table = Table::create().await;
    let a = adapter().await;
    let rows = format!("{}_v", table.name);
    exec(&table.owner, &format!("CREATE TABLE {rows} (v text)")).await;
    exec(
        &table.owner,
        &format!("INSERT INTO {rows} VALUES ('{}')", table.typo()),
    )
    .await;
    let mut leaks = Vec::new();
    for expression in ["v::regclass", "v::regproc", "current_setting(v)"] {
        let sql = format!("SELECT {expression} FROM {rows}");
        let rejection = rejected(&a, &sql).await;
        let told = format!("{:?}", (rejection.hint(), rejection.near_misses()));
        if rejection.hint().is_some() || !rejection.near_misses().is_empty() {
            leaks.push(format!("{sql}: {told}"));
        }
    }
    exec(&table.owner, &format!("DROP TABLE {rows}")).await;
    table.drop().await;
    assert!(leaks.is_empty(), "row data steered the answer: {leaks:#?}");
}

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

/// Over HTTP the call is still one audited `undefined_object`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_typo_over_http_is_audited_as_undefined_object() {
    let table = Table::create().await;
    let gateway = spawn_logged_in(
        &config_yaml(YAML),
        MockUser {
            sub: format!("hints-{}", Uuid::new_v4().simple()),
            email: "hints-e2e@example.com".to_string(),
            groups: vec!["engineers".to_string()],
        },
    )
    .await;
    let sql = format!("SELECT emial FROM {}", table.name);
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "run_query",
                        "arguments": { "server": "target", "database": "app", "sql": sql } }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    table.drop().await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    let text = response["result"]["content"][0]["text"].as_str();
    let body: Value = serde_json::from_str(text.expect("tool error text")).expect("JSON body");
    assert_eq!(body["position"], 8, "{body}");
    assert!(
        body["near_misses"]
            .as_array()
            .is_some_and(|names| names.iter().any(|n| n == "email")),
        "{body}"
    );
    let row = latest_audit(&gateway.state_db, &gateway.user_sub, "run_query", &sql).await;
    assert_eq!(row.outcome, "undefined_object");
    assert!(
        row.error_message
            .as_deref()
            .is_some_and(|m| m.contains("42703") && m.contains("emial")),
        "{:?}",
        row.error_message
    );
}
