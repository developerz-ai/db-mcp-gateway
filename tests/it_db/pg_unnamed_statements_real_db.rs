//! What a target connection may send for any pooler mode but *statement* to
//! serve it, checked on the wire and against the target (`bin/dev up`):
//!
//! - No prepared statement has a name. A name would outlive its transaction
//!   behind a transaction-mode pooler that tracks statements by their text,
//!   and fail the next caller's identical read after DDL (`0A000`).
//! - Nothing is parsed or bound outside a transaction. The driver syncs
//!   between `Parse` and `Bind`; outside a transaction such a pooler may send
//!   the two to different backends, and the `Bind` would run whatever another
//!   caller last parsed there.
//!
//! Unnamed statements cost one `Parse` per read, and the risk that a catalog
//! lookup of the driver's, sent as a simple query, destroys the statement
//! between its `Parse` and its `Bind` (sqlx 0.9.0 did: SQLSTATE `26000`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgDatabaseError, PgPoolOptions, PgSslMode};
use sqlx::{ConnectOptions, Connection, PgConnection};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::common::pg_target::{
    TARGET_DB, TARGET_HOST, TARGET_PASSWORD, TARGET_USER, adapter, ensure_read_role, is_yugabyte,
    owner_url, server, single_connection_adapter, target_port, writable_adapter, writable_database,
};
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::Password;
use db_mcp_gateway::exec::{
    Access, ActivityQuery, DbAdapter, ExecError, ExecQuery, ExecResult, ExplainQuery, GuardedSql,
    Identifier, PgAdapter, PoolSizing, QueryParam, SampleQuery, SchemaDetail, SchemaQuery,
    TableStatsQuery,
};

/// How long to wait for a state that must come. Below the ceiling on a
/// statement's timeout, which ends [`asleep`] if nothing else does.
const PATIENCE: Duration = Duration::from_secs(20);

/// A statement nothing but a cancel, a kill or its 30 s timeout ends.
fn asleep(access: Access) -> ExecQuery<'static> {
    ExecQuery {
        statement_timeout_ms: Some(30_000),
        ..statement("SELECT pg_sleep(120)", access)
    }
}

fn statement(sql: &str, access: Access) -> ExecQuery<'_> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: Some(10_000),
        row_limit: 100,
        access,
        dry_run: false,
        request_id: Uuid::new_v4(),
    }
}

fn read(sql: &str) -> ExecQuery<'_> {
    statement(sql, Access::ReadOnly)
}

async fn owner() -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

async fn run(owner: &sqlx::PgPool, sql: String) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone()))
        .execute(owner)
        .await
        .unwrap_or_else(|err| panic!("{sql}: {err}"));
}

/// Every shape of statement, asked while it runs what its session holds
/// prepared by name.
#[tokio::test]
#[serial_test::parallel(world)]
async fn no_statement_is_prepared_by_name() {
    let one = single_connection_adapter().await;
    let named = "(SELECT count(*) FROM pg_prepared_statements)::int AS named";
    // The view shows the driver's own named statements.
    let control: i32 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT {named}")))
        .fetch_one(&owner().await)
        .await
        .expect("control");
    assert_eq!(control, 1, "the view does not show a named statement");

    for (sql, params, types) in [
        (format!("SELECT {named}"), vec![], &["INT4"][..]),
        (
            format!("SELECT {named}, $1 AS p"),
            vec![QueryParam::Int(1)],
            &["INT4", "INT8"],
        ),
        // The text cast, described by the driver …
        (
            format!("SELECT {named}, relacl FROM pg_class WHERE relname = 'pg_class'"),
            vec![],
            &["INT4", "TEXT"],
        ),
        // … and by the cursor, its lookup having failed after the Parse.
        (
            format!("SELECT {named}, ev_action FROM pg_rewrite LIMIT $1"),
            vec![QueryParam::Int(1)],
            &["INT4", "TEXT"],
        ),
        (format!("SELECT {named}"), vec![], &["INT4"]),
    ] {
        let result = one
            .execute_with_params(read(&sql), &params)
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.rows.len(), 1, "{sql}");
        assert_eq!(result.rows[0][0], json!(0), "{sql}");
        assert_eq!(result.column_types, types, "{sql}");
    }

    let sql = format!("SELECT {named}");
    let written = writable_adapter()
        .await
        .execute(statement(&sql, Access::ReadWrite))
        .await
        .expect("write-tier statement");
    assert_eq!(written.rows[0][0], json!(0), "write tier");
}

/// On a connection that has seen neither the table nor its types, the driver
/// looks them up, by simple query, between the `Parse` of the statement it
/// serves and its `Bind`, which must then find the statement parsed again.
/// Callers with tables of their own do so side by side.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_first_seen_type_does_not_lose_the_statement() {
    ensure_read_role().await;
    let owner = owner().await;
    let mut names = Vec::new();
    for _ in 0..8 {
        let name = format!("dbmcp_seen_{}", Uuid::new_v4().simple());
        run(
            &owner,
            format!(
                "CREATE TYPE {name}_e AS ENUM ('a', 'b'); CREATE TYPE {name}_c AS (x int, e {name}_e); \
                 CREATE DOMAIN {name}_d AS int CHECK (value > 0); \
                 CREATE TABLE {name} (id int, e {name}_e, es {name}_e[], c {name}_c, d {name}_d); \
                 INSERT INTO {name} VALUES (1, 'a', '{{a,b}}', ROW(1, 'b'), 1)"
            ),
        )
        .await;
        names.push(name);
    }
    let tasks: Vec<_> = names
        .iter()
        .cloned()
        .map(|name| {
            tokio::spawn(async move {
                let wire = WireRecorder::start().await;
                let a = wire.adapter(1, DetachedTasks::new()).await;
                for round in 0..3 {
                    let sql = format!("SELECT * FROM {name} WHERE id = $1");
                    let found = a
                        .execute_with_params(read(&sql), &[QueryParam::Int(1)])
                        .await
                        .unwrap_or_else(|err| panic!("read {round}: {err:?}"));
                    assert_eq!(found.rows.len(), 1, "{found:?}");
                    assert_eq!(found.columns, ["id", "e", "es", "c", "d"]);
                    assert_eq!(found.rows[0][..2], [json!(1), json!("a")], "{found:?}");
                    assert_eq!(found.rows[0][2], json!(["a", "b"]), "{found:?}");
                    assert_eq!(found.rows[0][4], json!(1), "{found:?}");
                    if round == 0 {
                        assert_parsed_again(&wire.take(), &sql);
                    }
                    let none = a
                        .execute(read(&format!("SELECT * FROM {name} WHERE false")))
                        .await
                        .unwrap_or_else(|err| panic!("zero rows {round}: {err:?}"));
                    assert!(none.rows.is_empty());
                    assert_eq!(none.columns, found.columns);
                }
                let sql = format!("UPDATE {name} SET e = 'b' RETURNING e, es, c, d");
                wire.take();
                let written = a
                    .execute(statement(&sql, Access::ReadWrite))
                    .await
                    .unwrap_or_else(|err| panic!("write: {err:?}"));
                assert_parsed_again(&wire.take(), &sql);
                assert_eq!(written.rows_affected, Some(1));
                assert_eq!(written.rows[0][0], json!("b"), "{written:?}");
                assert_eq!(written.rows[0][1], json!(["a", "b"]), "{written:?}");
            })
        })
        .collect();
    let outcomes = futures::future::join_all(tasks).await;
    for name in names {
        run(
            &owner,
            format!(
                "DROP TABLE {name}; DROP TYPE {name}_c; DROP TYPE {name}_e; DROP DOMAIN {name}_d"
            ),
        )
        .await;
    }
    for outcome in outcomes {
        outcome.expect("reads and writes of a first-seen type");
    }
}

/// `seen`, one call's traffic, has `sql` parsed, then a lookup, then `sql`
/// parsed again as the last thing parsed before it is bound.
fn assert_parsed_again(seen: &Seen, sql: &str) {
    let parses_sql = |(kind, text): &(u8, String)| *kind == b'P' && text.contains(sql);
    let first = seen.messages.iter().position(parses_sql);
    let first = first.unwrap_or_else(|| panic!("{sql}: never parsed"));
    let rest = &seen.messages[first..];
    // The last Bind: a question of the gateway's own may come before it.
    let bind = rest.iter().rposition(|(kind, _)| *kind == b'B');
    let until_bind = &rest[..bind.unwrap_or_else(|| panic!("{sql}: never bound"))];
    let lookup = until_bind.iter().rposition(|(kind, _)| *kind == b'Q');
    let lookup = lookup.unwrap_or_else(|| panic!("{sql}: no lookup in {until_bind:?}"));
    let last_parse = until_bind.iter().rposition(|(kind, _)| *kind == b'P');
    let last_parse = last_parse.expect("the first parse at least");
    assert!(last_parse > lookup, "{sql}: {until_bind:?}");
    assert!(parses_sql(&until_bind[last_parse]), "{sql}: {until_bind:?}");
}

/// The same `SELECT *` from several callers at once, again after each change
/// of the table: no read fails, and every header is the table's as it now
/// stands — the zero-row read's included, which has nothing but its
/// description to go by.
#[tokio::test]
#[serial_test::parallel(world)]
async fn reads_after_a_schema_change_see_the_new_table() {
    // A YugabyteDB read on a catalog a DDL just moved is a retryable `40001`.
    if is_yugabyte() {
        return;
    }
    let owner = owner().await;
    let table = format!("dbmcp_evolving_{}", Uuid::new_v4().simple());
    run(
        &owner,
        format!("CREATE TABLE {table} (c0 int); INSERT INTO {table} VALUES (1), (2)"),
    )
    .await;
    let adapter = adapter().await;
    let all_rows = format!("SELECT * FROM {table}");
    let zero_rows = format!("SELECT * FROM {table} WHERE c0 < 0");
    let mut columns = vec!["c0".to_string()];
    for at in 1..=12 {
        let reads = [&all_rows, &all_rows, &zero_rows];
        let found = futures::future::join_all(reads.map(|sql| adapter.execute(read(sql)))).await;
        for (found, rows) in found.into_iter().zip([2, 2, 0]) {
            let found = found.unwrap_or_else(|err| panic!("{columns:?}: {err:?}"));
            assert_eq!(found.columns, columns);
            assert_eq!(found.rows.len(), rows);
            assert!(found.rows.iter().all(|row| row.len() == columns.len()));
        }
        run(&owner, format!("ALTER TABLE {table} ADD COLUMN c{at} int")).await;
        columns.push(format!("c{at}"));
    }
    run(&owner, format!("DROP TABLE {table}")).await;
}

/// A read of `table`, whose column `c<n>` is `n` in both rows but for `c0`,
/// the row's number.
struct Shape {
    condition: &'static str,
    params: Vec<QueryParam>,
    /// The `c0` of the rows that satisfy `condition`.
    rows: &'static [i64],
    /// A further column, which needs the text cast.
    extra: Option<&'static str>,
}

/// Plain, without rows, with params, and by both routes to the text cast.
fn shapes() -> [Shape; 5] {
    let plain = || Shape {
        condition: "true",
        params: vec![],
        rows: &[1, 2],
        extra: None,
    };
    [
        plain(),
        Shape {
            condition: "c0 < 0",
            rows: &[],
            ..plain()
        },
        Shape {
            condition: "c0 = $1",
            params: vec![QueryParam::Int(2)],
            rows: &[2],
            ..plain()
        },
        Shape {
            extra: Some("SELECT relacl FROM pg_class WHERE oid = 'pg_class'::regclass"),
            ..plain()
        },
        Shape {
            extra: Some("SELECT ev_action FROM pg_rewrite LIMIT 1"),
            ..plain()
        },
    ]
}

impl Shape {
    /// `gate` is evaluated before any row of `table`.
    fn sql(&self, table: &str, gate: &str) -> String {
        let extra = self.extra.map(|sql| format!(", ({sql}) AS extra"));
        format!(
            "SELECT t.*{} FROM {table} t WHERE {gate} AND {} ORDER BY c0",
            extra.unwrap_or_default(),
            self.condition
        )
    }

    /// `found` is this read's answer on a table with `c0` to `c<last>`.
    fn assert_answer(&self, found: Result<ExecResult, ExecError>, last: usize, sql: &str) {
        let found = found.unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        let mut columns: Vec<String> = (0..=last).map(|at| format!("c{at}")).collect();
        columns.extend(self.extra.map(|_| "extra".to_string()));
        assert_eq!(found.columns, columns, "{sql}");
        assert_eq!(found.rows.len(), self.rows.len(), "{sql}: {found:?}");
        for (row, c0) in found.rows.iter().zip(self.rows) {
            let mut own = vec![json!(c0)];
            own.extend((1..=last).map(|at| json!(at)));
            assert_eq!(row[..=last], own, "{sql}");
            assert_eq!(row.len(), columns.len(), "{sql}");
            if self.extra.is_some() {
                assert!(row[last + 1].is_string(), "{sql}: {row:?}");
            }
        }
    }
}

async fn create_evolving(owner: &sqlx::PgPool) -> String {
    let table = format!("dbmcp_evolving_{}", Uuid::new_v4().simple());
    run(
        owner,
        format!("CREATE TABLE {table} (c0 int); INSERT INTO {table} VALUES (1), (2)"),
    )
    .await;
    table
}

fn add_column(table: &str, at: usize) -> String {
    format!("ALTER TABLE {table} ADD COLUMN c{at} int DEFAULT {at}")
}

async fn connect() -> (PgConnection, i32) {
    let mut conn = PgConnection::connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut conn)
        .await
        .expect("pid");
    (conn, pid)
}

async fn execute(conn: &mut PgConnection, sql: String) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone()))
        .execute(conn)
        .await
        .unwrap_or_else(|err| panic!("{sql}: {err}"));
}

/// Wait for `condition` over `pg_stat_activity r`, the backend of
/// `request_id`, with `$2` = `pid`.
async fn observe(owner: &sqlx::PgPool, condition: &str, request_id: Uuid, pid: i32) {
    let deadline = Instant::now() + PATIENCE;
    let sql = format!(
        "SELECT EXISTS (SELECT FROM pg_stat_activity r \
         WHERE r.application_name LIKE $1 AND {condition})"
    );
    loop {
        let seen: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.clone()))
            .bind(format!("dbmcp-{}-%", request_id.simple()))
            .bind(pid)
            .fetch_one(owner)
            .await
            .expect("pg_stat_activity");
        if seen {
            return;
        }
        assert!(Instant::now() < deadline, "never observed: {condition}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const READ_WAITS_FOR_PID: &str = "$2 = ANY(pg_blocking_pids(r.pid))";
const PID_WAITS_FOR_READ: &str = "r.pid = ANY(pg_blocking_pids($2))";

/// A read that meets an `ALTER TABLE` in progress waits for it and answers
/// with the table it leaves.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_read_blocked_by_a_schema_change_answers_with_the_new_table() {
    // YugabyteDB has neither the lock nor `pg_blocking_pids` for it.
    if is_yugabyte() {
        return;
    }
    let owner = owner().await;
    let table = create_evolving(&owner).await;
    let adapter = adapter().await;
    let (mut alter, alter_pid) = connect().await;
    for (shape, at) in shapes().iter().zip(1..) {
        execute(&mut alter, format!("BEGIN; {}", add_column(&table, at))).await;
        let sql = shape.sql(&table, "true");
        let victim = ExecQuery {
            statement_timeout_ms: Some(30_000),
            ..read(&sql)
        };
        let request_id = victim.request_id;
        let (found, ()) = tokio::join!(adapter.execute_with_params(victim, &shape.params), async {
            observe(&owner, READ_WAITS_FOR_PID, request_id, alter_pid).await;
            execute(&mut alter, "COMMIT".to_string()).await;
        });
        shape.assert_answer(found, at, &sql);
    }
    run(&owner, format!("DROP TABLE {table}")).await;
}

/// The reverse: an `ALTER TABLE` waits for a running read, which answers
/// with the table it was described on; the next read has the new one.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_schema_change_waits_for_a_running_read() {
    // No advisory locks to hold the read with, nor `pg_blocking_pids`.
    if is_yugabyte() {
        return;
    }
    let owner = owner().await;
    let table = create_evolving(&owner).await;
    let adapter = adapter().await;
    let (mut keeper, keeper_pid) = connect().await;
    let (mut alter, alter_pid) = connect().await;
    for (shape, at) in shapes().iter().zip(1..) {
        // The read runs into a lock the test holds, and stays there.
        let key = i64::from(Uuid::new_v4().as_fields().0);
        execute(&mut keeper, format!("SELECT pg_advisory_lock({key})")).await;
        let gate = format!("(SELECT pg_advisory_xact_lock({key}) IS NOT NULL)");
        let sql = shape.sql(&table, &gate);
        let victim = ExecQuery {
            statement_timeout_ms: Some(30_000),
            ..read(&sql)
        };
        let request_id = victim.request_id;
        let (found, ()) = tokio::join!(adapter.execute_with_params(victim, &shape.params), async {
            observe(&owner, READ_WAITS_FOR_PID, request_id, keeper_pid).await;
            let ((), ()) = tokio::join!(execute(&mut alter, add_column(&table, at)), async {
                observe(&owner, PID_WAITS_FOR_READ, request_id, alter_pid).await;
                let unlock = format!("SELECT pg_advisory_unlock({key})");
                execute(&mut keeper, unlock).await;
            });
        });
        shape.assert_answer(found, at - 1, &sql);
        let sql = shape.sql(&table, "true");
        let next = adapter.execute_with_params(read(&sql), &shape.params);
        shape.assert_answer(next.await, at, &sql);
    }
    run(&owner, format!("DROP TABLE {table}")).await;
}

/// "cached plan must not change result type" from a plan a function keeps —
/// a SQL-level prepared statement whose table changes with the search path —
/// comes once the statement is running: its own error, never a retry. So is
/// any other `0A000`, raised by a function under that very message or by the
/// server.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_stale_plan_inside_a_running_statement_is_not_retryable() {
    let owner = owner().await;
    let name = format!("dbmcp_stale_{}", Uuid::new_v4().simple());
    run(
        &owner,
        format!(
            "CREATE SCHEMA {name}_a; CREATE SCHEMA {name}_b; \
             CREATE TABLE {name}_a.t (x int); CREATE TABLE {name}_b.t (x int, y text); \
             CREATE FUNCTION {name}() RETURNS int LANGUAGE plpgsql AS $$ BEGIN \
             PERFORM set_config('search_path', '{name}_a', true); \
             EXECUTE 'PREPARE {name}_p AS SELECT * FROM t'; \
             PERFORM set_config('search_path', '{name}_b', true); \
             EXECUTE 'EXECUTE {name}_p'; RETURN 1; END $$; \
             CREATE FUNCTION {name}_raise() RETURNS int LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION 'cached plan must not change result type' \
             USING ERRCODE = '0A000'; END $$"
        ),
    )
    .await;
    let adapter = adapter().await;
    let writer = writable_adapter().await;
    let stale = format!("SELECT {name}()");
    let insert = format!("INSERT INTO {name}_a.t SELECT {name}()");
    let raised = format!("SELECT {name}_raise()");
    let unsupported = "SELECT 1 UNION SELECT 2 FOR UPDATE";
    // The fixture raises that very error, from inside the function.
    let raw = sqlx::raw_sql(sqlx::AssertSqlSafe(stale.clone()))
        .execute(&owner)
        .await
        .map(|_| ());
    let outcomes = [
        (adapter.execute(read(&stale)).await, stale.as_str()),
        (
            writer.execute(statement(&insert, Access::ReadWrite)).await,
            insert.as_str(),
        ),
        (adapter.execute(read(&raised)).await, raised.as_str()),
        (adapter.execute(read(unsupported)).await, unsupported),
    ];
    run(
        &owner,
        format!(
            "DROP FUNCTION {name}(); DROP FUNCTION {name}_raise(); \
             DROP SCHEMA {name}_a CASCADE; DROP SCHEMA {name}_b CASCADE"
        ),
    )
    .await;
    let raw = raw.expect_err("the fixture's plan goes stale");
    let raw = raw.as_database_error().expect("server error");
    let raw = raw.downcast_ref::<PgDatabaseError>();
    assert_eq!(raw.code(), "0A000");
    assert_eq!(raw.routine(), Some("RevalidateCachedQuery"));
    assert!(raw.r#where().is_some());
    for (outcome, sql) in outcomes {
        assert_refused(outcome, "0A000", sql);
    }
}

/// The same error for the statement's own plan, at its `Bind`: nothing ran —
/// the function in it would have raised — so the call is retryable, and the
/// retry answers. A read and a write.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_plan_stale_before_the_statement_runs_is_retryable() {
    let owner = owner().await;
    let name = format!("dbmcp_bind_{}", Uuid::new_v4().simple());
    run(
        &owner,
        format!(
            "CREATE SCHEMA {name}_b; CREATE TABLE {name} (x int); INSERT INTO {name} VALUES (1); \
             CREATE TABLE {name}_b.{name} (x int, y text); \
             CREATE FUNCTION {name}_ran() RETURNS int VOLATILE LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'ran' USING ERRCODE = 'P0001'; END $$"
        ),
    )
    .await;
    let switch = SearchPathSwitch::start(&name).await;
    let mut target = server();
    target.port = switch.port;
    target.databases[0].write_role = Some(TARGET_USER.to_string());
    target.databases[0].write_password = Some(Password::Literal(TARGET_PASSWORD.into()));
    let a = PgAdapter::open(
        &target,
        &target.databases[0],
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("adapter over the switch");
    let mut outcomes = Vec::new();
    for (sql, access) in [
        (
            format!("SELECT *, public.{name}_ran() FROM {name}"),
            Access::ReadOnly,
        ),
        (
            format!("UPDATE {name} SET x = 2 RETURNING *, public.{name}_ran()"),
            Access::ReadWrite,
        ),
    ] {
        switch.armed.store(true, Ordering::SeqCst);
        let stale = a.execute(statement(&sql, access)).await;
        let answer = std::mem::take(&mut *switch.answer.lock().unwrap());
        // Again, its plan sound: now it runs, as far as its own error.
        let again = a.execute(statement(&sql, access)).await;
        outcomes.push((sql, stale, answer, again));
    }
    let plain = a.execute(read(&format!("SELECT * FROM {name}"))).await;
    run(
        &owner,
        format!("DROP FUNCTION {name}_ran(); DROP SCHEMA {name}_b CASCADE; DROP TABLE {name}"),
    )
    .await;
    for (sql, stale, answer, again) in outcomes {
        // What the target answered to the Bind: that error, before a
        // BindComplete, and with no context.
        let error = answer.first().expect("a Bind was intercepted");
        assert_eq!(error.kind, Some(b'E'), "{sql}: {answer:?}");
        let field = |code: u8| {
            let mut fields = error.body().split(|b| *b == 0);
            fields.find(|f| f.first() == Some(&code)).map(|f| &f[1..])
        };
        assert_eq!(field(b'C'), Some(&b"0A000"[..]), "{sql}");
        assert_eq!(field(b'R'), Some(&b"RevalidateCachedQuery"[..]), "{sql}");
        assert_eq!(field(b'W'), None, "{sql}");
        assert!(
            matches!(stale, Err(ExecError::Unavailable)),
            "{sql}: {stale:?}"
        );
        assert_refused(again, "P0001", &sql);
    }
    let plain = plain.expect("untouched table");
    assert_eq!(plain.rows, vec![vec![json!(1)]], "the write left no trace");
}

/// One protocol message. Only a connection's first, the startup, has no
/// type byte.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    kind: Option<u8>,
    raw: Vec<u8>,
}

impl Frame {
    fn body(&self) -> &[u8] {
        &self.raw[usize::from(self.kind.is_some()) + 4..]
    }
}

/// Cuts a byte stream, however TCP splits it, into whole messages.
struct Frames {
    startup_pending: bool,
    pending: Vec<u8>,
}

impl Frames {
    fn from_client() -> Self {
        Self {
            startup_pending: true,
            pending: Vec::new(),
        }
    }

    fn from_server() -> Self {
        Self {
            startup_pending: false,
            pending: Vec::new(),
        }
    }

    /// The messages `bytes` completes.
    fn feed(&mut self, bytes: &[u8]) -> Vec<Frame> {
        self.pending.extend_from_slice(bytes);
        let (mut frames, mut at) = (Vec::new(), 0);
        while let Some(end) = self.end_of_message(at) {
            let raw = self.pending[at..end].to_vec();
            let kind = (!self.startup_pending).then(|| raw[0]);
            self.startup_pending = false;
            frames.push(Frame { kind, raw });
            at = end;
        }
        self.pending.drain(..at);
        frames
    }

    /// Where the message at `at` ends, once all of it is here.
    fn end_of_message(&self, at: usize) -> Option<usize> {
        let len_at = at + usize::from(!self.startup_pending);
        let len = self.pending.get(len_at..len_at + 4)?;
        let end = len_at + u32::from_be_bytes(len.try_into().unwrap()) as usize;
        (end <= self.pending.len()).then_some(end)
    }
}

/// A message as it stands on the wire.
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = (body.len() as u32 + 4).to_be_bytes();
    [&[kind], &len[..], body].concat()
}

/// A TCP forwarder to the target that, once each time it is `armed`, changes
/// the transaction's search path between the `Parse` and the `Bind` of a
/// statement over `table` — what makes the server find its plan stale.
struct SearchPathSwitch {
    port: u16,
    armed: Arc<AtomicBool>,
    /// The target's answer to the `Bind` after the switch, up to its
    /// ReadyForQuery.
    answer: Arc<Mutex<Vec<Frame>>>,
}

impl SearchPathSwitch {
    async fn start(table: &str) -> Self {
        let listener = TcpListener::bind((TARGET_HOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (armed, answer): (Arc<AtomicBool>, Arc<Mutex<Vec<Frame>>>) = Default::default();
        let (arm, record, table) = (armed.clone(), answer.clone(), table.to_owned());
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let (arm, record, table) = (arm.clone(), record.clone(), table.clone());
                tokio::spawn(Self::serve(client, arm, record, table));
            }
        });
        Self {
            port,
            armed,
            answer,
        }
    }

    /// The driver reads a batch's whole answer before it sends the next, so
    /// the target has nothing in flight when a `Bind` arrives.
    async fn serve(
        mut client: TcpStream,
        armed: Arc<AtomicBool>,
        answer: Arc<Mutex<Vec<Frame>>>,
        table: String,
    ) {
        let mut server = connect_target(&client).await;
        let (mut client_chunk, mut server_chunk) = (vec![0u8; 65536], vec![0u8; 65536]);
        let (mut client_frames, mut server_frames) = (Frames::from_client(), Frames::from_server());
        let (mut parsed, mut answering) = (false, false);
        loop {
            tokio::select! {
                read = client.read(&mut client_chunk) => {
                    let Ok(n @ 1..) = read else { return };
                    for frame in client_frames.feed(&client_chunk[..n]) {
                        if frame.kind == Some(b'P') {
                            let table = table.as_bytes();
                            parsed = frame.body().windows(table.len()).any(|w| w == table);
                        }
                        if frame.kind == Some(b'B') && parsed && armed.swap(false, Ordering::SeqCst)
                        {
                            server.write_all(&switch_path(&table)).await.unwrap();
                            swallow_answer(&mut server, &mut server_frames).await;
                            answer.lock().unwrap().clear();
                            answering = true;
                        }
                        if server.write_all(&frame.raw).await.is_err() {
                            return;
                        }
                    }
                }
                read = server.read(&mut server_chunk) => {
                    let Ok(n @ 1..) = read else { return };
                    for frame in server_frames.feed(&server_chunk[..n]) {
                        if answering {
                            answering = frame.kind != Some(b'Z');
                            answer.lock().unwrap().push(frame.clone());
                        }
                        if client.write_all(&frame.raw).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// The target's end of a forwarded connection. Neither end waits to fill a
/// packet: the small writes of a relay would each cost a delayed ACK, and
/// the gateway's own short budgets with it.
async fn connect_target(client: &TcpStream) -> TcpStream {
    let server = TcpStream::connect((TARGET_HOST, target_port()))
        .await
        .expect("target-db reachable; run `bin/dev up`");
    client.set_nodelay(true).expect("nodelay");
    server.set_nodelay(true).expect("nodelay");
    server
}

/// Read `server` up to its ReadyForQuery, which must leave the transaction
/// usable.
async fn swallow_answer(server: &mut TcpStream, frames: &mut Frames) {
    assert!(frames.pending.is_empty(), "an answer was still in flight");
    let mut chunk = vec![0u8; 65536];
    loop {
        let n = server.read(&mut chunk).await.unwrap();
        assert!(n > 0, "target closed the connection");
        for frame in frames.feed(&chunk[..n]) {
            if frame.kind == Some(b'Z') {
                assert_eq!(frame.body(), b"T", "the switch failed");
                return;
            }
        }
    }
}

/// `set_config` over the extended protocol under a name of its own: a simple
/// query would destroy the unnamed statement waiting for its `Bind`.
fn switch_path(table: &str) -> Vec<u8> {
    let sql = format!("SELECT set_config('search_path', '{table}_b', true)");
    [
        message(b'P', &[b"switch\0", sql.as_bytes(), b"\0\0\0"].concat()),
        message(b'B', b"\0switch\0\0\0\0\0\0\0"),
        message(b'E', b"\0\0\0\0\0"),
        message(b'C', b"Sswitch\0"),
        message(b'S', b""),
    ]
    .concat()
}

/// A TCP forwarder to the target that reads both directions of every
/// connection and keeps what a transaction-mode pooler could not serve.
struct WireRecorder {
    port: u16,
    seen: Arc<Mutex<Seen>>,
}

#[derive(Default)]
struct Seen {
    /// Every Parse, Bind and simple query, in the order they came.
    messages: Vec<(u8, String)>,
    violations: Vec<String>,
}

/// One connection's transaction state, as its server last reported it.
#[derive(Default)]
struct Session {
    in_transaction: bool,
    /// Queries and Syncs not answered yet: what follows one before its
    /// answer runs in a state nobody has seen.
    unanswered: usize,
}

impl WireRecorder {
    async fn start() -> Self {
        let listener = TcpListener::bind((TARGET_HOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Seen>> = Arc::default();
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let server = connect_target(&client).await;
                let (from_client, to_client) = client.into_split();
                let (from_server, to_server) = server.into_split();
                let session: Arc<Mutex<Session>> = Arc::default();
                let (state, record) = (session.clone(), record.clone());
                tokio::spawn(forward(
                    from_client,
                    to_server,
                    Frames::from_client(),
                    move |frame| {
                        let mut session = state.lock().unwrap();
                        record.lock().unwrap().client(&mut session, frame);
                    },
                ));
                tokio::spawn(forward(
                    from_server,
                    to_client,
                    Frames::from_server(),
                    move |frame| session.lock().unwrap().server(frame),
                ));
            }
        });
        Self { port, seen }
    }

    /// An adapter of both tiers whose every connection is recorded.
    async fn adapter(&self, max_connections: u32, detached: DetachedTasks) -> PgAdapter {
        let mut target = server();
        target.port = self.port;
        target.databases = vec![writable_database()];
        let sizing = PoolSizing {
            max_connections,
            ..PoolSizing::default()
        };
        PgAdapter::open(&target, &target.databases[0], sizing, detached)
            .await
            .expect("adapter over the recorder")
    }

    fn parsed(&self, needle: &str) -> bool {
        self.seen.lock().unwrap().sent(b'P', needle)
    }

    /// What was recorded since the last call.
    fn take(&self) -> Seen {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

impl Session {
    fn server(&mut self, frame: &Frame) {
        if frame.kind == Some(b'Z') {
            self.unanswered = self.unanswered.saturating_sub(1);
            self.in_transaction = frame.body() != b"I";
        }
    }
}

impl Seen {
    /// Whether a message of `kind` holding `needle` was seen.
    fn sent(&self, kind: u8, needle: &str) -> bool {
        self.messages
            .iter()
            .any(|(seen, text)| *seen == kind && text.contains(needle))
    }

    fn client(&mut self, session: &mut Session, frame: &Frame) {
        let body = frame.body();
        let text = String::from_utf8_lossy(body);
        let Some(kind) = frame.kind else {
            return;
        };
        if matches!(kind, b'P' | b'B' | b'Q') {
            self.messages.push((kind, text.to_string()));
        }
        // Parse starts with the statement's name; Bind with the portal's,
        // then the statement's; Describe and Close with which of the two
        // they are for, then its name.
        let name = match kind {
            // A simple query and a Sync are each answered with the state.
            b'Q' | b'S' => {
                session.unanswered += 1;
                return;
            }
            b'P' => body.split(|b| *b == 0).next(),
            b'B' => body.split(|b| *b == 0).nth(1),
            b'D' | b'C' => body[1..].split(|b| *b == 0).next(),
            // Execute and Flush name no statement.
            b'E' | b'H' => None,
            _ => return,
        };
        let what = kind as char;
        if name.is_some_and(|name| !name.is_empty()) {
            self.violations
                .push(format!("{what} names a statement: {text:?}"));
        }
        if !session.in_transaction || session.unanswered > 0 {
            self.violations
                .push(format!("{what} outside a transaction: {text:?}"));
        }
    }
}

/// Copy `from` to `to` in whole messages, showing each to `observe` before it
/// is passed on.
async fn forward(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    mut frames: Frames,
    observe: impl Fn(&Frame),
) {
    let mut chunk = vec![0u8; 65536];
    while let Ok(n @ 1..) = from.read(&mut chunk).await {
        let mut whole = Vec::new();
        for frame in frames.feed(&chunk[..n]) {
            observe(&frame);
            whole.extend_from_slice(&frame.raw);
        }
        if to.write_all(&whole).await.is_err() {
            return;
        }
    }
    let _ = to.shutdown().await;
}

/// One connection's start and one query of each protocol.
fn sample_stream() -> Vec<u8> {
    let startup = b"\0\x03\0\0user\0u\0\0";
    let len = (startup.len() as u32 + 4).to_be_bytes();
    [
        [&len[..], startup].concat(),
        message(b'Q', b"BEGIN\0"),
        message(b'P', b"\0SELECT * FROM t\0\0\0"),
        message(b'D', b"S\0"),
        message(b'S', b""),
        message(b'B', b"\0\0\0\0\0\0\0\0"),
        message(b'E', b"\0\0\0\0\0"),
        message(b'S', b""),
    ]
    .concat()
}

/// However the bytes arrive, the same messages come out, none early.
#[test]
#[serial_test::parallel(world)]
fn the_decoder_does_not_depend_on_how_tcp_splits_the_stream() {
    let stream = sample_stream();
    let whole = Frames::from_client().feed(&stream);
    let kinds: Vec<Option<u8>> = whole.iter().map(|frame| frame.kind).collect();
    let expected = [None]
        .into_iter()
        .chain(b"QPDSBES".iter().copied().map(Some));
    assert_eq!(kinds, expected.collect::<Vec<_>>());
    let parse = &whole[2];
    assert_eq!(parse.body(), b"\0SELECT * FROM t\0\0\0");

    let (mut one, mut fed, mut out) = (Frames::from_client(), 0, Vec::new());
    for byte in &stream {
        fed += 1;
        for frame in one.feed(std::slice::from_ref(byte)) {
            out.push(frame);
            let complete: usize = out.iter().map(|frame| frame.raw.len()).sum();
            assert_eq!(complete, fed, "a message came out before its last byte");
        }
    }
    assert_eq!(out, whole);
    assert!(one.pending.is_empty());
    for cut in 0..stream.len() {
        let mut frames = Frames::from_client();
        let mut out = frames.feed(&stream[..cut]);
        out.extend(frames.feed(&stream[cut..]));
        assert_eq!(out, whole, "cut at {cut}");
    }
    let raw: Vec<u8> = whole.into_iter().flat_map(|frame| frame.raw).collect();
    assert_eq!(raw, stream, "nothing is lost in forwarding");
}

/// The recorder's rules on their own: every extended message is judged by
/// the state the server last reported, and one sent behind an unanswered
/// query is judged outside any transaction.
#[test]
#[serial_test::parallel(world)]
fn the_recorder_judges_by_the_state_the_server_reported() {
    let client = Frames::from_client().feed(&sample_stream());
    let ready = |state: &[u8]| Frames::from_server().feed(&message(b'Z', state)).remove(0);

    // BEGIN answered, then each Sync: nothing to flag.
    let (mut seen, mut session) = (Seen::default(), Session::default());
    for frame in &client {
        seen.client(&mut session, frame);
        if matches!(frame.kind, Some(b'Q' | b'S')) {
            session.server(&ready(b"T"));
        }
    }
    assert_eq!(seen.violations, Vec::<String>::new());
    let kinds: Vec<u8> = seen.messages.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, b"QPB");
    assert!(seen.sent(b'Q', "BEGIN") && seen.sent(b'P', "SELECT * FROM t"));
    assert!(!seen.sent(b'P', "BEGIN"));

    // BEGIN refused, or not answered yet: P, D, B and E are all flagged.
    for answered in [true, false] {
        let (mut seen, mut session) = (Seen::default(), Session::default());
        session.in_transaction = !answered;
        for frame in &client {
            seen.client(&mut session, frame);
            if answered && matches!(frame.kind, Some(b'Q' | b'S')) {
                session.server(&ready(b"I"));
            }
        }
        let kinds: String = seen.violations.iter().map(|v| &v[..1]).collect();
        assert_eq!(kinds, "PDBE", "{:?}", seen.violations);
        assert!(seen.violations.iter().all(|v| v.contains(" outside a ")));
    }

    // A name, wherever one can stand.
    for (kind, body) in [
        (b'P', &b"s\0SELECT 1\0\0\0"[..]),
        (b'B', b"\0s\0\0\0\0\0\0\0"),
        (b'D', b"Ss\0"),
        (b'C', b"Ss\0"),
    ] {
        let mut session = Session {
            in_transaction: true,
            unanswered: 0,
        };
        let mut seen = Seen::default();
        let frame = Frames::from_server().feed(&message(kind, body)).remove(0);
        seen.client(&mut session, &frame);
        assert_eq!(seen.violations.len(), 1, "{:?}", seen.violations);
        assert!(seen.violations[0].contains(" names a statement"));
    }
}

/// `outcome` is the target's refusal of `sql`, with `sqlstate`.
fn assert_refused(outcome: Result<ExecResult, ExecError>, sqlstate: &str, sql: &str) {
    let Err(ExecError::Rejected(rejection)) = outcome else {
        panic!("{sql}: {outcome:?}")
    };
    assert_eq!(rejection.sqlstate(), sqlstate, "{sql}");
}

/// The recorder sees what it is there for: the driver's own defaults.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_wire_recorder_flags_what_a_pooler_cannot_serve() {
    let wire = WireRecorder::start().await;
    let options = PgConnectOptions::new()
        .host(TARGET_HOST)
        .port(wire.port)
        .username(TARGET_USER)
        .password(TARGET_PASSWORD)
        .database(TARGET_DB)
        .ssl_mode(PgSslMode::Disable);
    let select = || sqlx::query("SELECT $1::int").bind(1).persistent(false);

    let mut conn = options.connect().await.expect("connect");
    select().execute(&mut conn).await.expect("no transaction");
    let seen = wire.take();
    for what in ["P", "D", "B", "E"] {
        let flag = format!("{what} outside a transaction");
        assert!(
            seen.violations.iter().any(|v| v.starts_with(&flag)),
            "{flag}: {:?}",
            seen.violations
        );
    }

    let mut tx = conn.begin().await.expect("begin");
    select().execute(&mut *tx).await.expect("unnamed");
    let seen = wire.take();
    assert_eq!(seen.violations, Vec::<String>::new());
    assert!(seen.sent(b'P', "SELECT $1::int"));
    sqlx::query("SELECT 1")
        .execute(&mut *tx)
        .await
        .expect("named");
    let seen = wire.take();
    assert!(
        seen.violations
            .iter()
            .any(|v| v.starts_with("P names a statement")),
        "{:?}",
        seen.violations
    );
    assert!(!seen.violations.iter().any(|v| v.contains("outside")));
}

/// Every operation of the adapter, over connections of both tiers and their
/// cancel pools: succeeding, refused, timed out, cut short at the row cap,
/// cancelled, dropped at any point, and with its backend killed.
#[tokio::test]
#[serial_test::parallel(world)]
async fn every_target_statement_is_servable_by_a_transaction_mode_pooler() {
    ensure_read_role().await;
    let owner = owner().await;
    let name = format!("dbmcp_wire_{}", Uuid::new_v4().simple());
    run(
        &owner,
        format!(
            "CREATE TYPE {name}_e AS ENUM ('a'); CREATE TYPE {name}_c AS (e {name}_e); \
             CREATE DOMAIN {name}_d AS int; \
             CREATE TABLE {name} (id int PRIMARY KEY, e {name}_e, es {name}_e[], c {name}_c, d {name}_d); \
             INSERT INTO {name} VALUES (1, 'a', '{{a}}', ROW('a'), 1)"
        ),
    )
    .await;
    let wire = WireRecorder::start().await;
    let detached = DetachedTasks::new();
    let a = wire.adapter(2, detached.clone()).await;
    let id = Uuid::new_v4;

    // Reads: a failed statement first, so the first-seen types after it are
    // looked up on a connection that has just rolled back.
    let nope = format!("SELECT nope FROM {name}");
    for (sql, sqlstate) in [
        ("SELECT 1 / 0", "22012"),
        ("SELECT 1 / 0, ev_action FROM pg_rewrite LIMIT 1", "22012"),
    ] {
        assert_refused(a.execute(read(sql)).await, sqlstate, sql);
    }
    // The near-miss lookup behind an undefined name gives up, silently, after
    // 200 ms: on a busy box it is asked for until it got as far as the wire.
    for (sql, sqlstate, lookup) in [
        (nope.as_str(), "42703", "quote_ident(a.attname)"),
        (
            "SELECT * FROM dbmcp_no_such_table",
            "42P01",
            "quote_ident(c.relname)",
        ),
    ] {
        let deadline = Instant::now() + PATIENCE;
        while !wire.parsed(lookup) {
            assert!(Instant::now() < deadline, "{sql}: no near-miss lookup");
            assert_refused(a.execute(read(sql)).await, sqlstate, sql);
        }
    }
    let star = format!("SELECT * FROM {name}");
    let none = format!("SELECT e FROM {name} WHERE false");
    for (sql, rows) in [
        (star.as_str(), 1),
        (none.as_str(), 0),
        ("SELECT relacl FROM pg_class WHERE relname = 'pg_class'", 1),
        ("SELECT ev_action FROM pg_rewrite LIMIT 1", 1),
    ] {
        let result = a
            .execute(read(sql))
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.rows.len(), rows, "{sql}");
        assert!(!result.truncated && !result.columns.is_empty(), "{sql}");
    }
    let capped = read("SELECT generate_series(1, 100000)");
    let capped_id = capped.request_id;
    let capped = a.execute(capped).await.expect("capped read");
    assert!(capped.truncated);
    assert_eq!(capped.rows.len(), 100);
    let all = format!("SELECT * FROM {name} WHERE id = $1");
    let found = a
        .execute_with_params(read(&all), &[QueryParam::Int(1)])
        .await
        .expect("params");
    assert_eq!(found.rows[0][1], json!("a"));
    // A timeout, until one came in the statement itself, not before it.
    let timed_out = "SELECT pg_sleep(60), 'timed out'";
    let deadline = Instant::now() + PATIENCE;
    while !wire.parsed(timed_out) {
        assert!(Instant::now() < deadline, "never timed out in the sleep");
        let slow = ExecQuery {
            statement_timeout_ms: Some(500),
            ..read(timed_out)
        };
        let outcome = a.execute(slow).await;
        assert!(matches!(outcome, Err(ExecError::Timeout)), "{outcome:?}");
    }

    // Every other read operation.
    for detail in [
        SchemaDetail::Schemas,
        SchemaDetail::Names,
        SchemaDetail::Columns,
        SchemaDetail::Full,
    ] {
        a.describe_schema(SchemaQuery {
            schema: Some("public"),
            table: (detail != SchemaDetail::Schemas).then_some(name.as_str()),
            search: None,
            detail,
            statement_timeout_ms: None,
            row_limit: 10,
            sample_limit: 0,
            request_id: id(),
        })
        .await
        .map(|found| assert!(!found.rows.is_empty(), "{detail:?}"))
        .unwrap_or_else(|err| panic!("{detail:?}: {err:?}"));
    }
    let sampled = a
        .sample(SampleQuery {
            schema: Identifier::parse("public").unwrap(),
            table: Identifier::parse(&name).unwrap(),
            statement_timeout_ms: None,
            row_limit: 1,
            request_id: id(),
        })
        .await
        .expect("sample");
    assert_eq!(sampled.rows.len(), 1);
    let stats = a
        .table_stats(TableStatsQuery {
            schema: "public",
            table: Some(&name),
            statement_timeout_ms: None,
            row_limit: 1,
            request_id: id(),
        })
        .await
        .expect("table_stats");
    assert_eq!(stats.rows.len(), 1);
    let update = format!("UPDATE {name} SET d = d + 1 RETURNING *");
    for (sql, access, analyze) in [
        (all.replace("$1", "1"), Access::ReadOnly, true),
        (update.clone(), Access::ReadWrite, false),
    ] {
        a.explain(ExplainQuery {
            sql: GuardedSql::parse(&sql, access).expect("guarded"),
            analyze,
            statement_timeout_ms: None,
            request_id: id(),
        })
        .await
        .map(|plan| assert!(!plan.rows.is_empty(), "explain {sql}"))
        .unwrap_or_else(|err| panic!("explain {sql}: {err:?}"));
    }

    // Writes: committed, rolled back, refused.
    for dry_run in [false, true] {
        let written = a
            .execute(ExecQuery {
                dry_run,
                ..statement(&update, Access::ReadWrite)
            })
            .await
            .expect("write");
        assert_eq!(written.rows_affected, Some(1));
    }
    let refused = format!("INSERT INTO {name} (id) VALUES (1)");
    let outcome = a.execute(statement(&refused, Access::ReadWrite)).await;
    assert_refused(outcome, "23505", &refused);

    // A cancel by request id, on each tier, while `db_activity` is asked.
    let mut by_request = Vec::new();
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let victim = asleep(access);
        let request_id = victim.request_id;
        let deadline = Instant::now() + PATIENCE;
        let (cancelled, ()) = tokio::join!(a.execute(victim), async {
            sleeping(&owner, request_id, deadline).await;
            let activity = a
                .db_activity(ActivityQuery {
                    statement_timeout_ms: None,
                    row_limit: 10,
                    request_id: id(),
                })
                .await
                .expect("db_activity");
            let listed = json!(activity.rows).to_string();
            assert!(listed.contains(&request_id.to_string()), "{listed}");
            assert!(a.cancel_request(request_id).await.expect("cancel"));
        });
        assert!(Instant::now() < deadline, "too late to tell from a timeout");
        assert!(
            matches!(cancelled, Err(ExecError::Cancelled)),
            "{cancelled:?}"
        );
        by_request.push(request_id);
    }

    // Dropped wherever it stands, a later point each time, up to its end.
    // Where a drop lands is chance, so nothing is asked of it but that the
    // calls after it are untouched and everything on the wire was servable.
    for sql in [
        "SELECT e.relname, pg_sleep(0.02) FROM pg_class e LIMIT 1",
        "SELECT ev_action FROM pg_rewrite LIMIT 2",
    ] {
        let started = Instant::now();
        a.execute(read(sql)).await.expect("undisturbed");
        let whole = started.elapsed();
        for at in 0..30 {
            // Cut short or done first.
            let cut = tokio::time::timeout(whole * at / 28, a.execute(read(sql))).await;
            if let Ok(outcome) = cut {
                outcome.unwrap_or_else(|err| panic!("after a drop: {sql}: {err:?}"));
            }
        }
        // Whatever the drops left behind, the next call finds nothing of it.
        a.execute(read(sql)).await.expect("after the drops");
    }

    // Dropped while its backend sleeps in it, on each tier: cancelled. One
    // deadline, set before the statement starts, for all of it: the
    // statement's own timeout, longer and running from later, cannot have
    // ended what is seen to have ended by then.
    let mut dropped_tags = Vec::new();
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let deadline = Instant::now() + PATIENCE;
        let victim = asleep(access);
        let request_id = victim.request_id;
        let tag = tokio::select! {
            outcome = a.execute(victim) => panic!("the sleep ended: {outcome:?}"),
            tag = sleeping(&owner, request_id, deadline) => tag,
        };
        loop {
            let busy = busy(&owner, &tag).await;
            assert!(
                Instant::now() < deadline,
                "the dropped call's backend was not cancelled in time"
            );
            if !busy {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        dropped_tags.push(tag);
    }

    // The backend killed under the statement.
    let victim = asleep(Access::ReadOnly);
    let request_id = victim.request_id;
    let deadline = Instant::now() + PATIENCE;
    let (killed, ()) = tokio::join!(a.execute(victim), async {
        let tag = sleeping(&owner, request_id, deadline).await;
        let killed: Vec<bool> = sqlx::query_scalar(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
        )
        .bind(&tag)
        .fetch_all(&owner)
        .await
        .expect("terminate");
        assert_eq!(killed, [true]);
    });
    assert!(Instant::now() < deadline, "too late to tell from a timeout");
    assert!(matches!(killed, Err(ExecError::Unavailable)), "{killed:?}");
    let recovered = a.execute(read("SELECT 1")).await.expect("recovered");
    assert_eq!(recovered.rows, vec![vec![json!(1)]]);

    detached.drain(PATIENCE).await.expect("drop cancels finish");
    run(
        &owner,
        format!("DROP TABLE {name}; DROP TYPE {name}_c; DROP TYPE {name}_e; DROP DOMAIN {name}_d"),
    )
    .await;
    let seen = wire.take();
    // Both routes to the text cast, up to the cast itself, and the calls
    // around them.
    for route in [
        "DECLARE dbmcp_columns",
        "q.c1::text AS \"relacl\"",
        "q.c1::text AS \"ev_action\"",
        "EXPLAIN",
        "UPDATE",
        "FROM pg_stat_activity",
    ] {
        assert!(seen.sent(b'P', route), "nothing parsed holds {route}");
    }
    // Every kind of cancel reached the target, as a simple query.
    let cancelled = |whom: &str| {
        seen.messages.iter().any(|(kind, text)| {
            *kind == b'Q' && text.contains("pg_cancel_backend") && text.contains(whom)
        })
    };
    for tag in &dropped_tags {
        assert!(cancelled(&format!("application_name = '{tag}'")), "{tag}");
    }
    let capped_tag = format!("application_name = 'dbmcp-{}-", capped_id.simple());
    assert!(cancelled(&capped_tag), "the row cap");
    for id in &by_request {
        assert!(
            cancelled(&format!("LIKE 'dbmcp-{}-%'", id.simple())),
            "{id}"
        );
    }
    assert!(
        seen.violations.is_empty(),
        "{} violations, first: {:?}",
        seen.violations.len(),
        &seen.violations[..seen.violations.len().min(5)]
    );
}

/// The tag of the backend sleeping for `request_id`, once it is: inside
/// `pg_sleep`, for the statement's text alone is there from its Parse on.
async fn sleeping(owner: &sqlx::PgPool, request_id: Uuid, deadline: Instant) -> String {
    loop {
        let tag: Option<String> = sqlx::query_scalar(
            "SELECT application_name FROM pg_stat_activity WHERE state = 'active' \
             AND wait_event_type = 'Timeout' AND wait_event = 'PgSleep' \
             AND application_name LIKE $1",
        )
        .bind(format!("dbmcp-{}-%", request_id.simple()))
        .fetch_optional(owner)
        .await
        .expect("pg_stat_activity");
        if let Some(tag) = tag {
            return tag;
        }
        assert!(Instant::now() < deadline, "{request_id} never slept");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Whether a backend still runs the transaction tagged `tag`.
async fn busy(owner: &sqlx::PgPool, tag: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM pg_stat_activity \
         WHERE state = 'active' AND application_name = $1)",
    )
    .bind(tag)
    .fetch_one(owner)
    .await
    .expect("pg_stat_activity")
}
