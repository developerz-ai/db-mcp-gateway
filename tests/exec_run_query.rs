//! Real-DB tests for the exec layer. Targets the local `target-db` brought up
//! by `bin/dev up` (Postgres on localhost:5434, user=app, db=app).
//!
//! These cover the things unit tests can't: `SET LOCAL statement_timeout`
//! actually firing, row-limit truncation against a live query, and the
//! `ExecError::Timeout` classification path. Slice 3's auth_e2e covers the
//! full agent → MCP → exec path.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{ExecError, PoolRegistry, run_query};

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
    let registry = PoolRegistry::new();
    registry
        .get_or_open(&server(), &database())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

#[tokio::test]
async fn quick_query_succeeds_with_columns_and_rows() {
    let p = pool().await;
    let result = run_query(&p, "SELECT 1::int8 AS n, 'hi'::text AS greeting", None, 100)
        .await
        .expect("simple SELECT runs");
    assert_eq!(
        result.columns,
        vec!["n".to_string(), "greeting".to_string()]
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0], serde_json::Value::from(1i64));
    assert_eq!(result.rows[0][1], serde_json::Value::from("hi"));
    assert!(!result.truncated);
}

#[tokio::test]
async fn row_limit_truncates_and_flags() {
    let p = pool().await;
    let result = run_query(&p, "SELECT generate_series(1, 1000)::int8 AS n", None, 10)
        .await
        .expect("series query runs");
    assert_eq!(result.rows.len(), 10);
    assert!(result.truncated, "expected truncated=true beyond row_limit");
}

/// The headline #4 acceptance: a query exceeding `statement_timeout_ms` is
/// killed at the DB and surfaces as the typed `ExecError::Timeout` — not a
/// raw sqlx error and never the underlying SQLSTATE string.
#[tokio::test]
async fn statement_timeout_kills_slow_query() {
    let p = pool().await;
    let err = run_query(&p, "SELECT pg_sleep(2)", Some(200), 10)
        .await
        .expect_err("pg_sleep(2) must exceed 200ms timeout");
    assert!(
        matches!(err, ExecError::Timeout),
        "expected ExecError::Timeout, got {err:?}"
    );
    // Display must NOT leak any underlying DB error string (e.g. SQLSTATE).
    let rendered = format!("{err}");
    assert!(
        rendered.contains("statement_timeout"),
        "unexpected message: {rendered}"
    );
    assert!(!rendered.contains("57014"), "leaked SQLSTATE: {rendered}");
}

/// SQL the DB rejects (e.g. unknown column) must surface as `ExecError::Sql`,
/// not as `Timeout` or `Unavailable`. Keeps the error-mapping correct so the
/// MCP layer can return the right error code to the agent.
#[tokio::test]
async fn syntax_error_classifies_as_sql() {
    let p = pool().await;
    let err = run_query(&p, "SELECT not_a_real_function()", None, 10)
        .await
        .expect_err("undefined function must fail");
    assert!(matches!(err, ExecError::Sql), "got {err:?}");
}
