//! Real-DB tests for the exec layer. Targets the local `target-db` brought up
//! by `bin/dev up` (Postgres on localhost:5434, user=app, db=app).
//!
//! These cover the things unit tests can't: `SET LOCAL statement_timeout`
//! actually firing, row-limit truncation against a live query, and the
//! `ExecError::Timeout` classification path. Slice 3's auth_e2e covers the
//! full agent → MCP → exec path.

mod common;

use std::time::{Duration, Instant};

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use common::pg_target::{
    TARGET_DB, TARGET_HOST, TARGET_PASSWORD, TARGET_PORT, TARGET_USER, adapter,
    single_connection_adapter,
};
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, MAX_RESULT_BYTES, RejectionKind,
};

fn query<'a>(sql: &'a str, timeout_ms: Option<u32>, row_limit: u32) -> ExecQuery<'a> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: timeout_ms,
        row_limit,
        access: Access::ReadOnly,
    }
}

/// A `query_write` caller's query.
fn write_query(sql: &str, row_limit: u32) -> ExecQuery<'_> {
    ExecQuery {
        access: Access::ReadWrite,
        ..query(sql, None, row_limit)
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

/// A statement the DB refuses comes back with its SQLSTATE and the server's
/// message, so the agent can fix the query; the kind picks the stable code.
#[tokio::test]
async fn db_rejection_carries_sqlstate_and_message() {
    let a = adapter().await;
    let err = a
        .execute(query("SELECT not_a_real_function()", None, 10))
        .await
        .expect_err("undefined function must fail");
    let ExecError::Rejected(rejection) = err else {
        panic!("expected Rejected, got {err:?}");
    };
    assert_eq!(rejection.sqlstate(), "42883");
    assert!(
        rejection.message().contains("not_a_real_function"),
        "{rejection}"
    );
    assert_eq!(rejection.kind(), RejectionKind::Other);

    let err = a
        .execute(query("SELECT nope FROM (SELECT 1 AS n) t", None, 10))
        .await
        .expect_err("undefined column must fail");
    let ExecError::Rejected(rejection) = err else {
        panic!("expected Rejected, got {err:?}");
    };
    assert_eq!(rejection.sqlstate(), "42703");
    assert_eq!(rejection.kind(), RejectionKind::UndefinedObject);
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
            access: Access::ReadOnly,
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
    // `timestamp` renders ISO-8601 with the `T` separator, no zone —
    // the spec (03-mcp-tools.md) requires it.
    assert_eq!(col("ts"), "2026-08-02T10:30:00");
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
        .execute(query("SELECT '[1,3)'::int4range AS r", None, 10))
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
        .execute(query("SELECT '[1,3)'::int4range::text AS r", None, 10))
        .await
        .expect("query runs");
    assert_eq!(cast.rows[0][0], "[1,3)");
}

/// A query that matches no rows must still report the column names it
/// selected. Without this the caller cannot tell "your filter matched nothing"
/// from "that table has no such columns" — the row loop never runs, so
/// `columns` was left empty (#136).
#[tokio::test]
async fn zero_row_result_still_reports_column_names() {
    let a = adapter().await;
    let result = a
        .execute(query(
            "SELECT 1::int8 AS n, 'x'::text AS label WHERE false",
            None,
            10,
        ))
        .await
        .expect("empty SELECT runs");

    assert!(result.rows.is_empty(), "query should match no rows");
    assert_eq!(
        result.columns,
        vec!["n".to_string(), "label".to_string()],
        "column names must survive an empty result set"
    );
    assert!(!result.truncated);
}

/// The non-empty path must keep taking names from the rows themselves — the
/// describe fallback is only for the empty case.
#[tokio::test]
async fn non_empty_result_column_names_are_unchanged() {
    let a = adapter().await;
    let result = a
        .execute(query("SELECT 42::int8 AS answer", None, 10))
        .await
        .expect("query runs");
    assert_eq!(result.columns, vec!["answer".to_string()]);
    assert_eq!(result.rows.len(), 1);
}

/// The describe fallback must also work when the query carries binds. Text
/// binds land at the OID layer as `unknown`; `SELECT $1 = $2 AS equal` would
/// give the planner nothing to infer from without the bind-type hints SQLx
/// attaches to `query.bind(...)`. This pins that path: zero-row + bound query
/// still surfaces the column name, and stays `truncated: false`.
#[tokio::test]
async fn zero_row_bound_query_still_reports_column_names() {
    let a = adapter().await;
    let result = a
        .execute(ExecQuery {
            sql: "SELECT $1 = $2 AS equal WHERE FALSE",
            binds: &["a", "b"],
            statement_timeout_ms: None,
            row_limit: 10,
            access: Access::ReadOnly,
        })
        .await
        .expect("bound empty SELECT runs");

    assert!(result.rows.is_empty(), "query should match no rows");
    assert_eq!(
        result.columns,
        vec!["equal".to_string()],
        "column name from a bound zero-row query must survive"
    );
    assert!(!result.truncated);
}

// ---------------------------------------------------------------------------
// Exec safety (plan 101 slice 05)
// ---------------------------------------------------------------------------

/// A fresh table owned by this test, created and dropped through the probe
/// pool (the adapter under test never runs DDL).
async fn scratch_table(probe: &sqlx::PgPool) -> String {
    let table = format!("exec_safety_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE \"{table}\" (id int PRIMARY KEY, v int NOT NULL DEFAULT 0)"
    ))
    .execute(probe)
    .await
    .expect("create scratch table");
    table
}

async fn drop_table(probe: &sqlx::PgPool, table: &str) {
    let _ = sqlx::query(&format!("DROP TABLE IF EXISTS \"{table}\""))
        .execute(probe)
        .await;
}

/// The dev role can write, so only the read-only transaction stands between
/// a read grant and a write here. `nextval` and `lo_from_bytea` are writes
/// the SQL guard would also stop — at this layer they must fail at the DB,
/// with no side effect.
#[tokio::test]
async fn read_access_cannot_write_on_a_write_capable_role() {
    let a = adapter().await;
    let probe = probe_pool().await;
    let seq = format!("exec_safety_seq_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SEQUENCE \"{seq}\""))
        .execute(&probe)
        .await
        .expect("create sequence");
    let objects_before: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_largeobject_metadata")
        .fetch_one(&probe)
        .await
        .expect("count large objects");

    for sql in [
        format!("SELECT nextval('\"{seq}\"')"),
        "SELECT lo_from_bytea(0, 'x')".to_string(),
    ] {
        let err = a
            .execute(query(&sql, None, 10))
            .await
            .expect_err("a write under read access must fail");
        let ExecError::Rejected(rejection) = err else {
            panic!("expected Rejected for `{sql}`, got {err:?}");
        };
        assert_eq!(
            rejection.sqlstate(),
            "25006",
            "read_only_sql_transaction for `{sql}`"
        );
    }

    let called: bool = sqlx::query_scalar(&format!("SELECT is_called FROM \"{seq}\""))
        .fetch_one(&probe)
        .await
        .expect("read sequence");
    let objects_after: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_largeobject_metadata")
        .fetch_one(&probe)
        .await
        .expect("count large objects");
    let _ = sqlx::query(&format!("DROP SEQUENCE \"{seq}\""))
        .execute(&probe)
        .await;
    assert!(!called, "nextval advanced the sequence under read access");
    assert_eq!(objects_before, objects_after, "a large object was created");
}

/// A `RETURNING` write past the row limit is drained and committed: the
/// response's `truncated` and `rows_affected` match what is in the table.
/// Rolling it back after reporting success was the bug.
#[tokio::test]
async fn truncated_write_commits_and_reports_rows_affected() {
    let a = adapter().await;
    let probe = probe_pool().await;
    let table = scratch_table(&probe).await;

    let inserted = a
        .execute(write_query(
            &format!(
                "INSERT INTO \"{table}\" (id) SELECT g FROM generate_series(1, 50) g RETURNING id"
            ),
            5,
        ))
        .await
        .expect("insert runs");
    let updated = a
        .execute(write_query(
            &format!("UPDATE \"{table}\" SET v = 1 RETURNING id, v"),
            5,
        ))
        .await
        .expect("update runs");
    let (rows, ones): (i64, i64) = sqlx::query_as(&format!(
        "SELECT count(*), count(*) FILTER (WHERE v = 1) FROM \"{table}\""
    ))
    .fetch_one(&probe)
    .await
    .expect("count rows");
    drop_table(&probe, &table).await;

    for (label, result) in [("insert", &inserted), ("update", &updated)] {
        assert_eq!(result.rows.len(), 5, "{label}: returned rows capped");
        assert!(result.truncated, "{label}: truncated flagged");
        assert_eq!(result.rows_affected, Some(50), "{label}: every row written");
    }
    assert_eq!(rows, 50, "insert committed");
    assert_eq!(ones, 50, "update committed");
}

/// A read reports no `rows_affected`; a write without `RETURNING` reports it
/// with no rows.
#[tokio::test]
async fn rows_affected_is_reported_for_writes_only() {
    let a = adapter().await;
    let probe = probe_pool().await;
    let table = scratch_table(&probe).await;

    let write = a
        .execute(write_query(
            &format!("INSERT INTO \"{table}\" (id) VALUES (1), (2)"),
            10,
        ))
        .await
        .expect("insert runs");
    let read = a
        .execute(query(&format!("SELECT id FROM \"{table}\""), None, 10))
        .await
        .expect("select runs");
    drop_table(&probe, &table).await;

    assert_eq!(write.rows_affected, Some(2));
    assert!(write.rows.is_empty() && !write.truncated);
    assert_eq!(read.rows_affected, None);
    assert_eq!(read.rows.len(), 2);
}

/// Session state set by one caller is gone for the next caller on the same
/// backend: a session `set_config`, a session advisory lock, the tag. The
/// pool has one connection, and the backend PID proves it was reused (reset,
/// not discarded).
#[tokio::test]
async fn no_session_state_survives_release() {
    let a = single_connection_adapter().await;
    let probe = probe_pool().await;
    let lock_key: i64 = rand_key();

    let first = a
        .execute(query(
            &format!(
                "SELECT pg_backend_pid() AS pid, \
                        set_config('search_path', 'pg_catalog', false) AS sp, \
                        pg_advisory_lock({lock_key}) AS lock, \
                        current_setting('application_name') AS app"
            ),
            None,
            10,
        ))
        .await
        .expect("first call runs");
    let second = a
        .execute(query(
            "SELECT pg_backend_pid() AS pid, current_setting('search_path') AS sp, \
                    current_setting('application_name') AS app",
            None,
            10,
        ))
        .await
        .expect("second call runs");

    let lock_free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_key)
        .fetch_one(&probe)
        .await
        .expect("probe takes the lock");
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&probe)
        .await;

    assert_eq!(first.rows[0][0], second.rows[0][0], "same backend reused");
    assert_ne!(
        second.rows[0][1], "pg_catalog",
        "search_path leaked across callers"
    );
    assert!(lock_free, "session advisory lock survived release");
    let (app1, app2) = (&first.rows[0][3], &second.rows[0][2]);
    assert!(
        app1.as_str().is_some_and(|s| s.starts_with("dbmcp-")),
        "transaction carries its tag: {app1}"
    );
    assert_ne!(app1, app2, "each transaction gets a fresh tag");
}

/// Wide rows stop at the byte budget well before the row limit, and the
/// connection is reusable afterwards.
#[tokio::test]
async fn wide_rows_truncate_at_the_byte_budget() {
    let a = single_connection_adapter().await;
    let one_mib = 1024 * 1024;
    let result = a
        .execute(query(
            &format!("SELECT repeat('x', {one_mib}) AS blob FROM generate_series(1, 64)"),
            None,
            1_000,
        ))
        .await
        .expect("wide query runs");
    assert!(result.truncated, "byte budget flags truncation");
    let bytes: usize = result
        .rows
        .iter()
        .map(|r| r[0].as_str().map_or(0, str::len))
        .sum();
    assert!(bytes <= MAX_RESULT_BYTES, "{bytes} bytes returned");
    assert!(result.rows.len() < 64, "stopped before the row limit");

    let next = a
        .execute(query("SELECT 1::int8 AS n", None, 10))
        .await
        .expect("connection reusable after a byte-capped read");
    assert_eq!(next.rows[0][0], 1);
}

/// A zero timeout must not reach Postgres as zero (= no limit).
#[tokio::test]
async fn zero_timeout_is_not_unlimited() {
    let a = adapter().await;
    let err = a
        .execute(query("SELECT pg_sleep(2)", Some(0), 10))
        .await
        .expect_err("a zero budget cannot run a 2 s sleep");
    assert!(matches!(err, ExecError::Timeout), "got {err:?}");
}

/// Waiting for a pooled connection is not the caller's query budget: with
/// the only connection pinned, a 100 ms query is `unavailable` after the
/// acquire timeout, not a `timeout`.
#[tokio::test]
async fn saturated_pool_is_unavailable_not_timeout() {
    let a = std::sync::Arc::new(single_connection_adapter().await);
    let holder = {
        let a = a.clone();
        tokio::spawn(async move {
            a.execute(query("SELECT pg_sleep(8)", Some(10_000), 1))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;

    let err = a
        .execute(query("SELECT 1", Some(100), 1))
        .await
        .expect_err("no connection is free");
    assert!(matches!(err, ExecError::Unavailable), "got {err:?}");
    holder.abort();
}

fn rand_key() -> i64 {
    i64::from_le_bytes(Uuid::new_v4().as_bytes()[..8].try_into().expect("8 bytes"))
}

// ---------------------------------------------------------------------------
// Decoder coverage (plan 101 slice 06)
// ---------------------------------------------------------------------------

/// JSON has no NaN or infinity; they must not collapse into SQL-NULL `null`.
#[tokio::test]
async fn non_finite_floats_render_as_strings() {
    let a = adapter().await;
    let r = a
        .execute(query(
            "SELECT 'NaN'::float8, 'Infinity'::float4, '-Infinity'::float8",
            None,
            10,
        ))
        .await
        .expect("query runs");
    assert_eq!(r.rows[0], vec!["NaN", "Infinity", "-Infinity"]);
}

#[tokio::test]
async fn arrays_intervals_and_inet_decode() {
    let a = adapter().await;
    let r = a
        .execute(query(
            "SELECT ARRAY['a', NULL]::text[], ARRAY[1, 2]::int4[], ARRAY[3]::int8[], \
                    ARRAY['11111111-2222-3333-4444-555555555555']::uuid[], \
                    '1 year 2 mons 3 days 04:05:06.5'::interval, \
                    '10.0.0.1'::inet, '10.0.0.0/8'::cidr, '::1/128'::inet",
            None,
            10,
        ))
        .await
        .expect("query runs");
    let row = &r.rows[0];
    assert_eq!(row[0], serde_json::json!(["a", null]));
    assert_eq!(row[1], serde_json::json!([1, 2]));
    assert_eq!(row[2], serde_json::json!([3]));
    assert_eq!(
        row[3],
        serde_json::json!(["11111111-2222-3333-4444-555555555555"])
    );
    assert_eq!(row[4], "P1Y2M3DT4H5M6.5S");
    assert_eq!(row[5], "10.0.0.1");
    assert_eq!(row[6], "10.0.0.0/8");
    assert_eq!(row[7], "::1");
}

#[tokio::test]
async fn enum_values_decode_as_their_label() {
    let a = adapter().await;
    let probe = probe_pool().await;
    let ty = format!("exec_mood_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE TYPE \"{ty}\" AS ENUM ('happy', 'sad')"))
        .execute(&probe)
        .await
        .expect("create enum");
    let r = a
        .execute(query(&format!("SELECT 'sad'::\"{ty}\" AS mood"), None, 10))
        .await;
    let _ = sqlx::query(&format!("DROP TYPE \"{ty}\""))
        .execute(&probe)
        .await;
    assert_eq!(r.expect("query runs").rows[0][0], "sad");
}
