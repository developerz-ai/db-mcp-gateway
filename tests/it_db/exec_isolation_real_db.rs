//! Real-DB tests for what one pooled caller may leave behind for the next.
//! Target: `target-db` (`bin/dev up`).

use std::time::{Duration, Instant};

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::exec::adapter::{Caller, for_caller};
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, ExecResult, PgAdapter, PoolSizing,
};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use crate::common::pg_target::{
    READ_ROLE, TARGET_USER, adapter, ensure_read_role, owner_url, server,
    single_connection_adapter, writable_adapter, writable_database,
};

fn read(sql: &str) -> ExecQuery<'_> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 100,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    }
}

async fn run(adapter: &PgAdapter, sql: &str) -> ExecResult {
    adapter
        .execute(read(sql))
        .await
        .unwrap_or_else(|err| panic!("`{sql}` runs: {err:?}"))
}

async fn owner() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

/// `set_config(…, false)` outlives the transaction. `RESET ALL` leaves
/// `role` alone, so the release hook has to reset it by name. Closing the
/// connection would pass too, so the backend pid must not change.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_role_set_by_one_caller_does_not_reach_the_next() {
    ensure_read_role().await;
    let a = single_connection_adapter().await;
    let set = format!("SELECT set_config('role', '{READ_ROLE}', false), pg_backend_pid()");
    let first = run(&a, &set).await;
    assert_eq!(first.rows[0][0], json!(READ_ROLE));

    let next = run(&a, "SELECT current_user::text, pg_backend_pid()").await;
    assert_eq!(next.rows[0][0], json!(TARGET_USER));
    assert_eq!(first.rows[0][1], next.rows[0][1], "same backend reused");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_session_authorization_set_by_one_caller_does_not_reach_the_next() {
    ensure_read_role().await;
    let a = single_connection_adapter().await;
    let set = format!(
        "SELECT set_config('session_authorization', '{READ_ROLE}', false), pg_backend_pid()"
    );
    let first = run(&a, &set).await;
    assert_eq!(first.rows[0][0], json!(READ_ROLE));

    let next = run(
        &a,
        "SELECT session_user::text, current_user::text, pg_backend_pid()",
    )
    .await;
    assert_eq!(next.rows[0][..2], [json!(TARGET_USER), json!(TARGET_USER)]);
    assert_eq!(first.rows[0][1], next.rows[0][2], "same backend reused");
}

/// A zero-row result still names its columns, but the statement the gateway
/// described to learn them must not stay on the pooled connection, where
/// `pg_prepared_statements` would show its text to the next caller.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_zero_row_statement_is_not_left_prepared_for_the_next_caller() {
    let a = single_connection_adapter().await;
    let marker = format!("marker-{}", Uuid::new_v4().simple());
    let first = run(&a, "SELECT pg_backend_pid()").await;
    let empty = run(&a, &format!("SELECT '{marker}'::text AS c WHERE false")).await;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.columns, vec!["c".to_string()]);

    let left = run(
        &a,
        "SELECT statement, pg_backend_pid() FROM pg_prepared_statements \
         UNION ALL SELECT NULL, pg_backend_pid()",
    )
    .await;
    assert!(
        !left.rows.iter().any(|row| row[0]
            .as_str()
            .is_some_and(|statement| statement.contains(&marker))),
        "statement text left behind: {:?}",
        left.rows
    );
    assert_eq!(first.rows[0][0], left.rows[0][1], "same backend reused");
}

/// The write tier's one connection, so consecutive writes share a backend.
async fn single_connection_writable_adapter() -> PgAdapter {
    ensure_read_role().await;
    let sizing = PoolSizing {
        max_connections: 1,
        ..PoolSizing::default()
    };
    PgAdapter::open(
        &server(),
        &writable_database(),
        sizing,
        DetachedTasks::new(),
    )
    .await
    .expect("target-db reachable; run `bin/dev up`")
}

async fn write(adapter: &PgAdapter, sql: &str) -> Result<ExecResult, ExecError> {
    adapter
        .execute(ExecQuery {
            access: Access::ReadWrite,
            ..read(sql)
        })
        .await
}

/// `lastval()` / `currval()` are session state: left alone they hand the
/// next caller on the write tier a key the previous one generated.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_sequence_value_drawn_by_one_caller_does_not_reach_the_next() {
    let owner = owner().await;
    let sequence = format!("dbmcp_iso_seq_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SEQUENCE {sequence}"))
        .execute(&owner)
        .await
        .expect("create sequence");

    let a = single_connection_writable_adapter().await;
    let drawn = write(
        &a,
        &format!("SELECT nextval('{sequence}'), lastval(), pg_backend_pid()"),
    )
    .await;
    let next = write(&a, "SELECT lastval()").await;
    let after = write(&a, "SELECT pg_backend_pid()").await;
    sqlx::query(&format!("DROP SEQUENCE {sequence}"))
        .execute(&owner)
        .await
        .expect("drop sequence");

    let drawn = drawn.expect("nextval runs on the write tier");
    assert_eq!(drawn.rows[0][0], drawn.rows[0][1]);
    let Err(ExecError::Rejected(rejection)) = next else {
        panic!("lastval() survived release: {next:?}");
    };
    // `object_not_in_prerequisite_state`: no sequence value in this session.
    assert_eq!(rejection.sqlstate(), "55000");
    let after = after.expect("the connection still serves");
    assert_eq!(drawn.rows[0][2], after.rows[0][0], "same backend reused");
}

/// A temporary table lives as long as its session, rows included.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_temporary_table_made_by_one_caller_does_not_reach_the_next() {
    let a = single_connection_writable_adapter().await;
    let table = format!("dbmcp_iso_tmp_{}", Uuid::new_v4().simple());
    write(&a, &format!("CREATE TEMP TABLE {table} AS SELECT 1 AS v"))
        .await
        .expect("create temp table");
    let first = write(&a, "SELECT pg_backend_pid()").await.expect("pid");

    let seen = write(
        &a,
        &format!("SELECT to_regclass('pg_temp.{table}')::text, pg_backend_pid()"),
    )
    .await
    .expect("lookup runs");
    assert_eq!(seen.rows[0][0], Value::Null, "temp table survived release");
    assert_eq!(first.rows[0][0], seen.rows[0][1], "same backend reused");
}

/// A write whose text stops resolving once it ran (here it narrows its own
/// transaction's `search_path`) must still commit: nothing may run inside
/// the write's transaction after the statement that could abort it.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_finished_write_commits_even_when_its_text_no_longer_parses() {
    let owner = owner().await;
    let table = format!("dbmcp_iso_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE TABLE {table} (v int NOT NULL)"))
        .execute(&owner)
        .await
        .expect("create table");
    sqlx::query(&format!("INSERT INTO {table} VALUES (0)"))
        .execute(&owner)
        .await
        .expect("seed");

    let a = writable_adapter().await;
    let sql = format!(
        "UPDATE {table} SET v = v + 1 \
         WHERE set_config('search_path', 'pg_catalog', true) IS NOT NULL"
    );
    let result = a
        .execute(ExecQuery {
            access: Access::ReadWrite,
            ..read(&sql)
        })
        .await
        .expect("the update runs");
    assert_eq!(result.rows_affected, Some(1));

    let v: i32 = sqlx::query_scalar(&format!("SELECT v FROM {table}"))
        .fetch_one(&owner)
        .await
        .expect("read back");
    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&owner)
        .await
        .expect("drop table");
    assert_eq!(v, 1, "reported as written, so it must be written");
}

/// The pool holds four connections. One caller may pin all but one of them;
/// its fourth query waits for its own share, not for the last connection.
#[tokio::test]
#[serial_test::parallel(world)]
async fn one_caller_cannot_hold_every_connection() {
    let a = std::sync::Arc::new(adapter().await);
    let greedy = Caller::new("greedy");
    let sleepers: Vec<_> = (0..4)
        .map(|_| {
            let (a, greedy) = (a.clone(), greedy.clone());
            tokio::spawn(for_caller(greedy, async move {
                a.execute(read("SELECT pg_sleep(3)")).await.map(|_| ())
            }))
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let started = Instant::now();
    let other = for_caller(Caller::new("other"), a.execute(read("SELECT 1::int4"))).await;
    let waited = started.elapsed();
    assert_eq!(other.expect("a connection is left").rows[0][0], json!(1));
    assert!(
        waited < Duration::from_millis(1_500),
        "waited {waited:?} behind another caller's queries"
    );

    for sleeper in sleepers {
        sleeper.await.expect("join").expect("each sleep completes");
    }
}

/// Values Postgres can hold and `chrono` cannot: rendered, not a panic.
#[tokio::test]
#[serial_test::parallel(world)]
async fn infinite_and_far_dates_render_as_text() {
    let a = adapter().await;
    let result = run(
        &a,
        "SELECT 'infinity'::timestamptz, '-infinity'::timestamptz, 'infinity'::timestamp, \
         '-infinity'::date, 'infinity'::date, \
         '294276-12-31 23:59:59.999999'::timestamp, '5874897-12-31'::date, \
         '4713-01-01 BC'::date, '24:00:00'::time, \
         '2024-02-29 12:34:56.5+00'::timestamptz, '2024-02-29 12:34:56.123456'::timestamp, \
         '2024-02-29'::date, '00:00:01'::time",
    )
    .await;
    let want: Vec<Value> = [
        "infinity",
        "-infinity",
        "infinity",
        "-infinity",
        "infinity",
        "+294276-12-31T23:59:59.999999",
        "+5874897-12-31",
        "-4712-01-01",
        "24:00:00",
        "2024-02-29T12:34:56.500+00:00",
        "2024-02-29T12:34:56.123456",
        "2024-02-29",
        "00:00:01",
    ]
    .into_iter()
    .map(Value::from)
    .collect();
    assert_eq!(result.rows[0], want);
}
