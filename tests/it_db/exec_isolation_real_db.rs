//! Real-DB tests for what one pooled caller may leave behind for the next,
//! and for what a target error may say. Target: `target-db` (`bin/dev up`).

use std::time::{Duration, Instant};

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password};
use db_mcp_gateway::exec::adapter::{Caller, for_caller};
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, ExecResult, PgAdapter, PoolSizing,
};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use crate::common::pg_target::{
    READ_ROLE, TARGET_USER, adapter, database, ensure_read_role, owner_url, server,
    single_connection_adapter, writable_adapter,
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
/// `role` alone, so the release hook has to reset it by name.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_role_set_by_one_caller_does_not_reach_the_next() {
    ensure_read_role().await;
    let a = single_connection_adapter().await;
    let set = format!("SELECT set_config('role', '{READ_ROLE}', false)");
    assert_eq!(run(&a, &set).await.rows[0][0], json!(READ_ROLE));

    let next = run(&a, "SELECT current_user::text").await;
    assert_eq!(next.rows[0][0], json!(TARGET_USER));
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_session_authorization_set_by_one_caller_does_not_reach_the_next() {
    ensure_read_role().await;
    let a = single_connection_adapter().await;
    let set = format!("SELECT set_config('session_authorization', '{READ_ROLE}', false)");
    assert_eq!(run(&a, &set).await.rows[0][0], json!(READ_ROLE));

    let next = run(&a, "SELECT session_user::text, current_user::text").await;
    assert_eq!(next.rows[0], vec![json!(TARGET_USER), json!(TARGET_USER)]);
}

/// A zero-row result still names its columns, but the statement the gateway
/// described to learn them must not stay on the pooled connection, where
/// `pg_prepared_statements` would show its text to the next caller.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_zero_row_statement_is_not_left_prepared_for_the_next_caller() {
    let a = single_connection_adapter().await;
    let marker = format!("marker-{}", Uuid::new_v4().simple());
    let empty = run(&a, &format!("SELECT '{marker}'::text AS c WHERE false")).await;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.columns, vec!["c".to_string()]);

    let left = run(&a, "SELECT statement FROM pg_prepared_statements").await;
    assert!(
        !left.rows.iter().any(|row| row[0]
            .as_str()
            .is_some_and(|statement| statement.contains(&marker))),
        "statement text left behind: {:?}",
        left.rows
    );
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

/// A data error quotes the offending value — row data. The SQLSTATE and the
/// sentence stay; the value does not. A name the caller spelled does.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_data_error_keeps_its_code_but_not_the_value() {
    let a = adapter().await;
    let err = a
        .execute(read(
            "SELECT v::int FROM (VALUES ('alice@example.com')) t(v)",
        ))
        .await
        .expect_err("not an integer");
    let ExecError::Rejected(rejection) = err else {
        panic!("expected a rejection, got {err:?}");
    };
    assert_eq!(rejection.sqlstate(), "22P02");
    assert!(
        rejection.message().starts_with("invalid input syntax"),
        "{rejection}"
    );
    assert!(!rejection.message().contains("alice"), "{rejection}");

    let err = a
        .execute(read("SELECT no_such_column FROM pg_class"))
        .await
        .expect_err("undefined column");
    let ExecError::Rejected(rejection) = err else {
        panic!("expected a rejection, got {err:?}");
    };
    assert!(
        rejection.message().contains("\"no_such_column\""),
        "{rejection}"
    );
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

/// The byte cap weighs what the gateway holds, not the wire form: two
/// million `int4`s are 16 MB on the wire and several times that decoded.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_row_is_weighed_by_its_decoded_size() {
    let a = adapter().await;
    let result = run(
        &a,
        "SELECT array_agg(g::int4) AS big FROM generate_series(1, 2000000) g",
    )
    .await;
    assert!(result.truncated);
    assert!(result.rows.is_empty());
    assert_eq!(result.columns, vec!["big".to_string()]);
}

/// One cell past the byte cap is refused from its wire length alone.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_cell_past_the_byte_cap_is_truncated_away() {
    let a = adapter().await;
    let result = run(&a, "SELECT repeat('x', 40000000) AS big").await;
    assert!(result.truncated);
    assert!(result.rows.is_empty());
}
