//! Real-DB tests for the exec layer. Targets the local `target-db` brought up
//! by `bin/dev up` (Postgres on localhost:5434, user=app, db=app).
//!
//! These cover the things unit tests can't: `SET LOCAL statement_timeout`
//! actually firing, row-limit truncation against a live query, and the
//! `ExecError::Timeout` classification path. Slice 3's auth_e2e covers the
//! full agent → MCP → exec path.

use std::time::{Duration, Instant};

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{DbAdapter, ExecError, ExecQuery, PgAdapter};

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

fn query<'a>(sql: &'a str, timeout_ms: Option<u32>, row_limit: u32) -> ExecQuery<'a> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: timeout_ms,
        row_limit,
    }
}

#[tokio::test]
async fn quick_query_succeeds_with_columns_and_rows() {
    let a = adapter().await;
    let result = a
        .execute(query(
            "SELECT 1::int8 AS n, 'hi'::text AS greeting",
            None,
            100,
        ))
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
    let a = adapter().await;
    let result = a
        .execute(query(
            "SELECT generate_series(1, 1000)::int8 AS n",
            None,
            10,
        ))
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
    let a = adapter().await;
    let err = a
        .execute(query("SELECT pg_sleep(2)", Some(200), 10))
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
    let a = adapter().await;
    let err = a
        .execute(query("SELECT not_a_real_function()", None, 10))
        .await
        .expect_err("undefined function must fail");
    assert!(matches!(err, ExecError::Sql), "got {err:?}");
}

/// Adapter's `kind()` reports `Postgres` and `health()` round-trips a
/// `SELECT 1`. Cheap but worth pinning so a future refactor doesn't quietly
/// regress the trait surface.
#[tokio::test]
async fn pg_adapter_reports_kind_and_health() {
    let a = adapter().await;
    assert_eq!(a.kind(), db_mcp_gateway::exec::AdapterKind::Postgres);
    a.health().await.expect("health check round-trips");
}

/// Separate pool to the SAME target DB, used to observe `pg_stat_activity`
/// independently of the adapter under test.
async fn probe_pool() -> sqlx::PgPool {
    let url = format!(
        "postgres://{TARGET_USER}:{TARGET_PASSWORD}@{TARGET_HOST}:{TARGET_PORT}/{TARGET_DB}"
    );
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

/// Count `active` backends whose current query carries `marker`. The marker
/// rides in a SQL comment, so it appears verbatim in `pg_stat_activity.query`
/// — while this probe's own query keeps the marker in a bound param, so it
/// never self-matches.
async fn active_with_marker(probe: &sqlx::PgPool, marker: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query LIKE $1",
    )
    .bind(format!("%{marker}%"))
    .fetch_one(probe)
    .await
    .expect("pg_stat_activity query runs")
}

/// Poll until the active-backend count for `marker` equals `want`, or give up
/// after `within`. Returns whether the target count was reached.
async fn wait_for_active_count(
    probe: &sqlx::PgPool,
    marker: &str,
    want: i64,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if active_with_marker(probe, marker).await == want {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Cancellation safety (CLAUDE.md *§Cancellation safety*): when the query
/// future is dropped (agent disconnect), the exec layer must fire
/// `pg_cancel_backend` so the backend stops promptly — NOT linger until
/// `statement_timeout`. Proven by watching `pg_stat_activity`: the slow query
/// must vanish within seconds of the drop, far faster than its 30s
/// sleep/timeout could account for on its own. Easy to regress: dropping the
/// `sqlx::Transaction` alone leaves the query running on the backend.
#[tokio::test]
async fn dropped_query_future_cancels_backend() {
    let a = adapter().await;
    let probe = probe_pool().await;
    // Unique marker so we match only THIS test's backend in pg_stat_activity.
    let marker = format!("cancel-probe-{}", Uuid::new_v4().simple());
    let sql = format!("SELECT pg_sleep(30) /* {marker} */");

    let task = tokio::spawn(async move {
        // Long DB-side timeout (clamped to the 30s ceiling) so the *cancel*,
        // not statement_timeout, is what stops the query.
        let q = ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: Some(30_000),
            row_limit: 10,
        };
        let _ = a.execute(q).await;
    });

    // The backend must actually be running our query before we cancel it.
    assert!(
        wait_for_active_count(&probe, &marker, 1, Duration::from_secs(5)).await,
        "slow query never became active — test setup failed"
    );

    // Drop the query future, as axum does when the agent disconnects.
    task.abort();

    // The detached pg_cancel_backend should clear the backend well within 5s
    // — the 30s sleep/timeout cannot account for a faster disappearance.
    assert!(
        wait_for_active_count(&probe, &marker, 0, Duration::from_secs(5)).await,
        "backend not cancelled within 5s — drop did not fire pg_cancel_backend"
    );
}
