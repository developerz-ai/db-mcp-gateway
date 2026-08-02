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

/// sqlx 0.8 rejects width-mismatched decodes at the OID layer: a
/// `SMALLINT` (`INT2`) won't come out through the `i32` probe, nor `REAL`
/// (`FLOAT4`) through `f64`. Without dedicated `i16`/`f32` branches the
/// fallback silently returns `Value::Null` — a data-integrity bug on
/// perfectly ordinary column types. This pins each numeric width to its
/// probe so a future refactor can't drop one and re-open the hole.
#[tokio::test]
async fn decodes_every_numeric_width_not_just_i64_and_f64() {
    let a = adapter().await;
    let result = a
        .execute(query(
            "SELECT 7::int2 AS s, 42::int4 AS i, 99::int8 AS b, \
             1.5::float4 AS r, 2.5::float8 AS d",
            None,
            10,
        ))
        .await
        .expect("mixed-width numeric SELECT runs");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0], serde_json::Value::from(7i16));
    assert_eq!(result.rows[0][1], serde_json::Value::from(42i32));
    assert_eq!(result.rows[0][2], serde_json::Value::from(99i64));
    assert_eq!(result.rows[0][3], serde_json::Value::from(1.5f32));
    assert_eq!(result.rows[0][4], serde_json::Value::from(2.5f64));
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

/// Regression for the #136 audit finding "row cap doesn't bound work":
/// sqlx always issues the portal `Execute` with `limit: 0` (no server-side
/// row cap), so breaking the Rust-side read loop early does NOT stop
/// Postgres from generating and queueing the rest of the result. Without an
/// active cancel on truncation, the next `.await` on that connection
/// (`COMMIT`) silently drains every remaining row before it can proceed —
/// on exactly the query shape a row cap exists to protect against.
///
/// `generate_series(1, 100_000_000)` is the amplifier: rows are produced
/// cheaply and continuously, so Postgres queues far more than the 5-row
/// cap wants long before we can break out of the loop. Under the pre-fix
/// always-commit path this test measured ~29s (full drain) against
/// ~565ms with cancel-on-truncate. Bounding this at 2s proves the cap
/// actually bounds server-side work, not just the client-visible row
/// count — a full drain cannot possibly finish that fast.
#[tokio::test]
async fn truncated_query_cancels_instead_of_draining_the_rest() {
    let a = adapter().await;
    let started = Instant::now();
    let result = a
        .execute(query(
            "SELECT generate_series(1, 100000000)::int8 AS n",
            Some(30_000),
            5,
        ))
        .await
        .expect("truncated query still succeeds, not times out");
    let elapsed = started.elapsed();

    assert_eq!(result.rows.len(), 5);
    assert!(result.truncated);
    assert!(
        elapsed < Duration::from_secs(2),
        "truncated query took {elapsed:?} — a 100M-row `generate_series` \
         streams cheaply-produced rows continuously, so postgres queues far \
         more than the row cap wants; if the connection has to drain that \
         instead of cancelling the backend, this takes several seconds. \
         Row cap did not bound server-side work (cancel-on-truncate regression)"
    );
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

// ---------------------------------------------------------------------------
// Decode fidelity (#136)
//
// `Value::Null` in a result row must mean SQL NULL and nothing else. These
// types used to fall through every probe and arrive at the caller as `null`,
// indistinguishable from a real NULL — a silently wrong answer for an agent
// acting on the data.
// ---------------------------------------------------------------------------

/// The types the audit called out — plus the date/time family — must come back
/// as their actual values, not `null`.
#[tokio::test]
async fn previously_nulled_types_decode_to_real_values() {
    let adapter = adapter().await;
    let result = adapter
        .execute(query(
            "SELECT '11111111-2222-3333-4444-555555555555'::uuid    AS u,
                    '2026-08-02T10:30:00Z'::timestamptz              AS tstz,
                    '2026-08-02 10:30:00'::timestamp                 AS ts,
                    '2026-08-02'::date                               AS d,
                    '10:30:00'::time                                 AS t,
                    '1234.5600'::numeric                             AS n,
                    '\\x0011ff'::bytea                               AS b",
            None,
            10,
        ))
        .await
        .expect("query runs");

    let row = &result.rows[0];
    let col = |name: &str| {
        let idx = result
            .columns
            .iter()
            .position(|c| c == name)
            .expect("column present");
        row[idx].clone()
    };

    for name in ["u", "tstz", "ts", "d", "t", "n", "b"] {
        assert!(
            !col(name).is_null(),
            "column `{name}` decoded to null — that is the #136 bug"
        );
    }
    assert_eq!(col("u"), "11111111-2222-3333-4444-555555555555");
    assert_eq!(col("ts"), "2026-08-02 10:30:00");
    assert_eq!(col("d"), "2026-08-02");
    assert_eq!(col("t"), "10:30:00");
    assert_eq!(col("b"), "\\x0011ff");
    // `numeric` keeps its trailing zeros: it is a decimal, not a float.
    assert_eq!(col("n"), "1234.5600");
    // RFC 3339, normalised to UTC.
    let tstz = col("tstz");
    let tstz = tstz.as_str().expect("timestamptz renders as a string");
    assert!(
        tstz.starts_with("2026-08-02T10:30:00"),
        "unexpected timestamptz rendering: {tstz}"
    );
}

/// `numeric` must survive as an exact decimal string. Rendering it as `f64`
/// would trade a visibly wrong answer for an invisible one on money columns:
/// this value needs 29 significant digits and `f64` carries ~15.
#[tokio::test]
async fn numeric_keeps_precision_a_float_would_lose() {
    let adapter = adapter().await;
    let exact = "12345678901234567890.123456789";
    let result = adapter
        .execute(query(&format!("SELECT '{exact}'::numeric AS n"), None, 10))
        .await
        .expect("query runs");

    let got = result.rows[0][0]
        .as_str()
        .expect("numeric renders as string");
    // Postgres ships numerics as base-10000 digit groups, so the decoded scale
    // rounds up to a multiple of 4 and can carry extra trailing zeros. Those
    // are cosmetic — every significant digit must survive verbatim.
    assert_eq!(got.trim_end_matches('0'), exact, "got {got}");
    assert_ne!(
        got,
        (exact.parse::<f64>().expect("parses")).to_string(),
        "numeric must not be routed through f64"
    );
}

/// SQL NULL still decodes to `null` — including for non-text types, where the
/// old `Option<String>` probe could not even reach the NULL check.
#[tokio::test]
async fn sql_null_decodes_to_null_for_every_type() {
    let adapter = adapter().await;
    let result = adapter
        .execute(query(
            "SELECT NULL::timestamptz, NULL::uuid, NULL::numeric, NULL::text, NULL::int4[]",
            None,
            10,
        ))
        .await
        .expect("query runs");
    for (idx, value) in result.rows[0].iter().enumerate() {
        assert!(
            value.is_null(),
            "column {idx} should be SQL NULL, got {value}"
        );
    }
}

/// A type the gateway can't render must be marked as such, never passed off as
/// NULL. The marker names the type so the caller knows to cast it.
#[tokio::test]
async fn unrenderable_type_is_marked_not_nulled() {
    let adapter = adapter().await;
    let result = adapter
        .execute(query("SELECT ARRAY[1,2,3] AS arr", None, 10))
        .await
        .expect("query runs");

    let value = &result.rows[0][0];
    assert!(
        !value.is_null(),
        "an unrenderable value must not masquerade as SQL NULL"
    );
    let named = value
        .get("unsupported_type")
        .and_then(|v| v.as_str())
        .expect("marker carries the postgres type name");
    assert!(!named.is_empty(), "type name should not be blank");

    // And the caller's documented workaround actually works.
    let cast = adapter
        .execute(query("SELECT ARRAY[1,2,3]::text AS arr", None, 10))
        .await
        .expect("query runs");
    assert_eq!(cast.rows[0][0], "{1,2,3}");
}
