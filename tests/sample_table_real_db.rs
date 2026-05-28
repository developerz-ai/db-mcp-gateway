//! Real-DB tests for `sample_table`: setup a table, sample it through the
//! exec layer the tool uses, and assert the shape. Identifier-safety unit
//! tests in `src/tools/sample_table.rs` already cover the regex; this file
//! proves the happy-path SQL works against a live Postgres.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{PoolRegistry, run_query};

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
        password: Password::Literal(TARGET_PASSWORD.to_string()),
        description: String::new(),
    }
}

async fn pool() -> sqlx::PgPool {
    PoolRegistry::new()
        .get_or_open(&server(), &database())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

fn fresh_schema_name() -> String {
    format!("sampletbl_{}", uuid::Uuid::new_v4().simple())
}

/// The exact same SQL `sample_table` would build, once identifiers have
/// passed the regex check. Confirms identifier interpolation + LIMIT
/// interpolation produce a query Postgres actually accepts and that the
/// row-cap/truncation semantics carry through from `exec::run_query`.
#[tokio::test]
async fn sample_returns_rows_with_truncation_flag() {
    let p = pool().await;
    let schema = fresh_schema_name();

    run_query(&p, &format!("CREATE SCHEMA \"{schema}\""), None, 10)
        .await
        .expect("create schema");
    run_query(
        &p,
        &format!("CREATE TABLE \"{schema}\".\"events\" (id int, name text)"),
        None,
        10,
    )
    .await
    .expect("create events");
    run_query(
        &p,
        &format!(
            "INSERT INTO \"{schema}\".\"events\" \
             SELECT g, 'event-' || g FROM generate_series(1, 100) g"
        ),
        None,
        10,
    )
    .await
    .expect("seed events");

    // Cap at 5 rows; mirror the LIMIT+1 trick `sample_table` uses so the
    // gateway-side truncation flag fires when more rows exist.
    let sql = format!("SELECT * FROM \"{schema}\".\"events\" LIMIT 6");
    let result = run_query(&p, &sql, None, 5)
        .await
        .expect("sample SELECT runs");

    let _ = run_query(&p, &format!("DROP SCHEMA \"{schema}\" CASCADE"), None, 10).await;

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
    let p = pool().await;
    let schema = fresh_schema_name();

    run_query(&p, &format!("CREATE SCHEMA \"{schema}\""), None, 10)
        .await
        .expect("create schema");
    run_query(
        &p,
        &format!("CREATE TABLE \"{schema}\".\"MixedCase\" (x int)"),
        None,
        10,
    )
    .await
    .expect("create MixedCase");
    run_query(
        &p,
        &format!("INSERT INTO \"{schema}\".\"MixedCase\" VALUES (1), (2), (3)"),
        None,
        10,
    )
    .await
    .expect("seed");

    let sql = format!("SELECT * FROM \"{schema}\".\"MixedCase\" LIMIT 10");
    let result = run_query(&p, &sql, None, 10)
        .await
        .expect("quoted identifier query runs");

    let _ = run_query(&p, &format!("DROP SCHEMA \"{schema}\" CASCADE"), None, 10).await;

    assert_eq!(result.rows.len(), 3);
}
