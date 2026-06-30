//! Real-DB tests for `sample_table`: setup a table, sample it through the
//! exec layer the tool uses, and assert the shape. Identifier-safety unit
//! tests in `src/tools/sample_table.rs` already cover the regex; this file
//! proves the happy-path SQL works against a live Postgres.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{DbAdapter, ExecError, ExecQuery, ExecResult, PgAdapter};

const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 5434;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";

fn server() -> Server {
    Server {
        name: "target".to_string(),
        kind: ServerKind::Postgres,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: TARGET_PORT,
        tls: Tls::Insecure,
        databases: vec![database()],
    }
}

fn database() -> Database {
    Database {
        name: TARGET_DB.to_string(),
        role: TARGET_USER.to_string(),
        password: Password::Literal(TARGET_PASSWORD.into()),
        description: String::new(),
        auth_database: None,
    }
}

async fn adapter() -> PgAdapter {
    PgAdapter::open(&server(), &database())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

async fn run(a: &PgAdapter, sql: &str) -> Result<ExecResult, ExecError> {
    a.execute(ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 10,
    })
    .await
}

fn fresh_schema_name() -> String {
    format!("sampletbl_{}", uuid::Uuid::new_v4().simple())
}

/// The exact same SQL `sample_table` would build, once identifiers have
/// passed the regex check. Confirms identifier interpolation + LIMIT
/// interpolation produce a query Postgres actually accepts and that the
/// row-cap/truncation semantics carry through from the adapter.
#[tokio::test]
async fn sample_returns_rows_with_truncation_flag() {
    let a = adapter().await;
    let schema = fresh_schema_name();

    run(&a, &format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    run(
        &a,
        &format!("CREATE TABLE \"{schema}\".\"events\" (id int, name text)"),
    )
    .await
    .expect("create events");
    run(
        &a,
        &format!(
            "INSERT INTO \"{schema}\".\"events\" \
             SELECT g, 'event-' || g FROM generate_series(1, 100) g"
        ),
    )
    .await
    .expect("seed events");

    // Cap at 5 rows; mirror the LIMIT+1 trick `sample_table` uses so the
    // gateway-side truncation flag fires when more rows exist.
    let sql = format!("SELECT * FROM \"{schema}\".\"events\" LIMIT 6");
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 5,
        })
        .await
        .expect("sample SELECT runs");

    let _ = run(&a, &format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    assert_eq!(result.rows.len(), 5);
    assert!(
        result.truncated,
        "expected truncated=true when more rows exist"
    );
    assert_eq!(result.columns, vec!["id".to_string(), "name".to_string()]);
}

/// Quoted-identifier SQL doesn't trip on Postgres' case-folding: an
/// unquoted `EVENTS` would be lowercased, but `"EVENTS"` is exact. This is
/// the same path `sample_table` takes when the regex accepts an uppercase
/// table name.
#[tokio::test]
async fn quoted_identifiers_are_case_sensitive() {
    let a = adapter().await;
    let schema = fresh_schema_name();

    run(&a, &format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    run(
        &a,
        &format!("CREATE TABLE \"{schema}\".\"MixedCase\" (x int)"),
    )
    .await
    .expect("create MixedCase");
    run(
        &a,
        &format!("INSERT INTO \"{schema}\".\"MixedCase\" VALUES (1), (2), (3)"),
    )
    .await
    .expect("seed");

    let sql = format!("SELECT * FROM \"{schema}\".\"MixedCase\" LIMIT 10");
    let result = run(&a, &sql).await.expect("quoted identifier query runs");

    let _ = run(&a, &format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    assert_eq!(result.rows.len(), 3);
}
