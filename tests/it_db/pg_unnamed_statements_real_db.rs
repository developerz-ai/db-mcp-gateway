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
use std::time::Duration;

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{ConnectOptions, Connection};
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
    for (sql, params) in [
        (format!("SELECT {named}"), vec![]),
        (format!("SELECT {named}, $1 AS p"), vec![QueryParam::Int(1)]),
        // The text cast, described by the driver …
        (
            format!("SELECT {named}, relacl FROM pg_class WHERE relname = 'pg_class'"),
            vec![],
        ),
        // … and by the cursor, its lookup having failed after the Parse.
        (
            format!("SELECT {named}, ev_action FROM pg_rewrite LIMIT $1"),
            vec![QueryParam::Int(1)],
        ),
        (format!("SELECT {named}"), vec![]),
    ] {
        let result = one
            .execute_with_params(read(&sql), &params)
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.rows[0][0], json!(0), "{sql}");
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
/// looks them up while the statement it serves is unnamed. Callers with
/// tables of their own do so side by side.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_first_seen_type_does_not_lose_the_statement() {
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
                let reader = single_connection_adapter().await;
                for round in 0..3 {
                    let sql = format!("SELECT * FROM {name} WHERE id = $1");
                    let found = reader
                        .execute_with_params(read(&sql), &[QueryParam::Int(1)])
                        .await
                        .unwrap_or_else(|err| panic!("read {round}: {err:?}"));
                    assert_eq!(found.rows[0][..2], [json!(1), json!("a")], "{found:?}");
                    let none = reader
                        .execute(read(&format!("SELECT * FROM {name} WHERE false")))
                        .await
                        .unwrap_or_else(|err| panic!("zero rows {round}: {err:?}"));
                    assert_eq!(none.columns, found.columns);
                }
                let sql = format!("UPDATE {name} SET e = 'b' RETURNING e, es, c, d");
                let written = writable_adapter()
                    .await
                    .execute(statement(&sql, Access::ReadWrite))
                    .await
                    .unwrap_or_else(|err| panic!("write: {err:?}"));
                assert_eq!(written.rows[0][0], json!("b"), "{written:?}");
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

/// The same `SELECT *` from several callers while the table gains columns:
/// no read fails, every row is as wide as its header, and no header goes
/// back to an older table — the zero-row read's included, which has nothing
/// but its description to go by.
#[tokio::test]
#[serial_test::parallel(world)]
async fn reads_survive_schema_changes_between_them() {
    // Concurrent DDL aborts a YugabyteDB read with a retryable `40001`.
    if is_yugabyte() {
        return;
    }
    let owner = owner().await;
    let table = format!("dbmcp_evolving_{}", Uuid::new_v4().simple());
    run(
        &owner,
        format!("CREATE TABLE {table} (id int); INSERT INTO {table} VALUES (1), (2)"),
    )
    .await;
    let adapter = Arc::new(adapter().await);
    let zero_rows = format!("SELECT * FROM {table} WHERE id < 0");
    let before = adapter.execute(read(&zero_rows)).await.expect("zero rows");
    assert_eq!(before.columns, ["id"]);
    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|at| {
            let (adapter, done) = (adapter.clone(), done.clone());
            let sql = match at {
                0 => zero_rows.clone(),
                _ => format!("SELECT * FROM {table}"),
            };
            tokio::spawn(async move {
                let mut failures = Vec::new();
                let mut width = 0;
                while !done.load(Ordering::Relaxed) {
                    match adapter.execute(read(&sql)).await {
                        Ok(result) => {
                            let columns = result.columns.len();
                            assert!(columns >= width, "{columns} columns after {width}");
                            width = columns;
                            let rows = if at == 0 { 0 } else { 2 };
                            assert_eq!(result.rows.len(), rows, "{result:?}");
                            assert!(result.rows.iter().all(|row| row.len() == columns));
                        }
                        Err(err) => failures.push(format!("{err:?}")),
                    }
                }
                failures
            })
        })
        .collect();
    for at in 0..20 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        run(&owner, format!("ALTER TABLE {table} ADD COLUMN c{at} int")).await;
    }
    let last = adapter
        .execute(read(&format!("SELECT * FROM {table}")))
        .await;
    let after = adapter.execute(read(&zero_rows)).await;
    done.store(true, Ordering::Relaxed);
    let outcomes = futures::future::join_all(readers).await;
    run(&owner, format!("DROP TABLE {table}")).await;
    for outcome in outcomes {
        assert_eq!(outcome.expect("reader"), Vec::<String>::new());
    }
    let last = last.expect("last read");
    assert_eq!(last.columns.len(), 21);
    let after = after.expect("zero rows");
    assert!(after.rows.is_empty());
    assert_eq!(after.columns, last.columns);
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
        let switched = !switch.armed.load(Ordering::SeqCst);
        // Again, its plan sound: now it runs, as far as its own error.
        outcomes.push((sql.clone(), stale, switched));
        assert_refused(a.execute(statement(&sql, access)).await, "P0001", &sql);
    }
    let plain = a.execute(read(&format!("SELECT * FROM {name}"))).await;
    run(
        &owner,
        format!("DROP FUNCTION {name}_ran(); DROP SCHEMA {name}_b CASCADE; DROP TABLE {name}"),
    )
    .await;
    for (sql, stale, switched) in outcomes {
        assert!(switched, "{sql}: no Bind was intercepted");
        assert!(
            matches!(stale, Err(ExecError::Unavailable)),
            "{sql}: {stale:?}"
        );
    }
    let plain = plain.expect("untouched table");
    assert_eq!(plain.rows, vec![vec![json!(1)]], "the write left no trace");
}

/// A TCP forwarder to the target that, once each time it is `armed`, changes
/// the transaction's search path between the `Parse` and the `Bind` of a
/// statement over `table` — what makes the server find its plan stale.
struct SearchPathSwitch {
    port: u16,
    armed: Arc<AtomicBool>,
}

impl SearchPathSwitch {
    async fn start(table: &str) -> Self {
        let listener = TcpListener::bind((TARGET_HOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let armed: Arc<AtomicBool> = Arc::default();
        let (arm, table) = (armed.clone(), table.to_owned());
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(Self::serve(client, arm.clone(), table.clone()));
            }
        });
        Self { port, armed }
    }

    /// The driver sends one batch and reads its whole answer before the
    /// next, so a batch is one read here and the two never interleave.
    async fn serve(mut client: TcpStream, armed: Arc<AtomicBool>, table: String) {
        let mut server = TcpStream::connect((TARGET_HOST, target_port()))
            .await
            .expect("target-db reachable; run `bin/dev up`");
        let (mut from_client, mut from_server) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut parsed = false;
        loop {
            tokio::select! {
                read = client.read(&mut from_client) => {
                    let Ok(n @ 1..) = read else { return };
                    let batch = &from_client[..n];
                    if batch[0] == b'P' {
                        parsed = batch.windows(table.len()).any(|w| w == table.as_bytes());
                    }
                    if batch[0] == b'B' && parsed && armed.swap(false, Ordering::SeqCst) {
                        server.write_all(&switch_path(&table)).await.unwrap();
                        let mut answer = Vec::new();
                        // ReadyForQuery, in a transaction: the answer's end.
                        while !answer.ends_with(b"Z\0\0\0\x05T") {
                            let n = server.read(&mut from_server).await.unwrap();
                            assert!(n > 0, "target closed the connection");
                            answer.extend_from_slice(&from_server[..n]);
                        }
                    }
                    if server.write_all(&from_client[..n]).await.is_err() {
                        return;
                    }
                }
                read = server.read(&mut from_server) => {
                    let Ok(n @ 1..) = read else { return };
                    if client.write_all(&from_server[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// `set_config` over the extended protocol under a name of its own: a simple
/// query would destroy the unnamed statement waiting for its `Bind`.
fn switch_path(table: &str) -> Vec<u8> {
    let sql = format!("SELECT set_config('search_path', '{table}_b', true)");
    let mut batch = Vec::new();
    for (kind, body) in [
        (b'P', [b"switch\0", sql.as_bytes(), b"\0\0\0"].concat()),
        (b'B', b"\0switch\0\0\0\0\0\0\0".to_vec()),
        (b'E', b"\0\0\0\0\0".to_vec()),
        (b'C', b"Sswitch\0".to_vec()),
        (b'S', Vec::new()),
    ] {
        batch.push(kind);
        batch.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
        batch.extend_from_slice(&body);
    }
    batch
}

/// A TCP forwarder to the target that reads both directions of every
/// connection and keeps what a transaction-mode pooler could not serve.
struct WireRecorder {
    port: u16,
    seen: Arc<Mutex<Seen>>,
}

#[derive(Default)]
struct Seen {
    /// The text of every Parse.
    parses: Vec<String>,
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
                let server = TcpStream::connect((TARGET_HOST, target_port()))
                    .await
                    .expect("target-db reachable; run `bin/dev up`");
                let (from_client, to_client) = client.into_split();
                let (from_server, to_server) = server.into_split();
                let session: Arc<Mutex<Session>> = Arc::default();
                let (state, record) = (session.clone(), record.clone());
                // The client's first message, the startup, has no type byte.
                tokio::spawn(forward(from_client, to_server, 1, move |kind, body| {
                    let mut session = state.lock().unwrap();
                    record.lock().unwrap().client(&mut session, kind, body);
                }));
                tokio::spawn(forward(from_server, to_client, 0, move |kind, body| {
                    if kind == b'Z' {
                        let mut session = session.lock().unwrap();
                        session.unanswered = session.unanswered.saturating_sub(1);
                        session.in_transaction = body.first() != Some(&b'I');
                    }
                }));
            }
        });
        Self { port, seen }
    }

    /// What was recorded since the last call.
    fn take(&self) -> Seen {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

impl Seen {
    fn client(&mut self, session: &mut Session, kind: u8, body: &[u8]) {
        // Parse starts with the statement's name; Bind with the portal's,
        // then the statement's; Describe with what it describes, then a name.
        let name_at = match kind {
            // A simple query and a Sync are each answered with the state.
            b'Q' | b'S' => {
                session.unanswered += 1;
                return;
            }
            b'P' => 0,
            b'B' => body.iter().position(|b| *b == 0).map_or(0, |end| end + 1),
            b'D' | b'C' => 1,
            b'E' => body.len().saturating_sub(5),
            _ => return,
        };
        let name = body[name_at..].split(|b| *b == 0).next().unwrap_or(&[]);
        let text = String::from_utf8_lossy(body);
        if kind == b'P' {
            self.parses.push(text.to_string());
        }
        if kind != b'E' && !name.is_empty() {
            self.violations
                .push(format!("{} names a statement: {text:?}", kind as char));
        }
        if !session.in_transaction || session.unanswered > 0 {
            self.violations
                .push(format!("{} outside a transaction: {text:?}", kind as char));
        }
    }
}

/// Copy `from` to `to`, calling `message` with every whole message before its
/// last byte is passed on. The first `untyped` messages have no type byte.
async fn forward(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    mut untyped: usize,
    message: impl Fn(u8, &[u8]),
) {
    let (mut chunk, mut pending) = (vec![0u8; 65536], Vec::new());
    while let Ok(n @ 1..) = from.read(&mut chunk).await {
        pending.extend_from_slice(&chunk[..n]);
        loop {
            let head = usize::from(untyped == 0);
            let Some(len) = pending.get(head..head + 4) else {
                break;
            };
            let end = head + u32::from_be_bytes(len.try_into().unwrap()) as usize;
            if pending.len() < end {
                break;
            }
            if untyped > 0 {
                untyped -= 1;
            } else {
                message(pending[0], &pending[5..end]);
            }
            pending.drain(..end);
        }
        if to.write_all(&chunk[..n]).await.is_err() {
            return;
        }
    }
    let _ = to.shutdown().await;
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
    assert!(
        seen.violations
            .iter()
            .any(|v| v.starts_with("P outside a transaction"))
            && seen
                .violations
                .iter()
                .any(|v| v.starts_with("B outside a transaction")),
        "{:?}",
        seen.violations
    );

    let mut tx = conn.begin().await.expect("begin");
    select().execute(&mut *tx).await.expect("unnamed");
    let seen = wire.take();
    assert_eq!(seen.violations, Vec::<String>::new());
    assert!(!seen.parses.is_empty());
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
    let mut target = server();
    target.port = wire.port;
    target.databases = vec![writable_database()];
    let detached = DetachedTasks::new();
    let a = PgAdapter::open(
        &target,
        &target.databases[0],
        PoolSizing {
            max_connections: 2,
            ..PoolSizing::default()
        },
        detached.clone(),
    )
    .await
    .expect("adapter over the recorder");
    let id = Uuid::new_v4;

    // Reads: a failed statement first, so the first-seen types after it are
    // looked up on a connection that has just rolled back.
    let nope = format!("SELECT nope FROM {name}");
    for (sql, sqlstate) in [
        ("SELECT 1 / 0", "22012"),
        (nope.as_str(), "42703"),
        ("SELECT * FROM dbmcp_no_such_table", "42P01"),
        ("SELECT 1 / 0, ev_action FROM pg_rewrite LIMIT 1", "22012"),
    ] {
        assert_refused(a.execute(read(sql)).await, sqlstate, sql);
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
    let capped = a
        .execute(read("SELECT generate_series(1, 100000)"))
        .await
        .expect("capped read");
    assert!(capped.truncated);
    assert_eq!(capped.rows.len(), 100);
    let all = format!("SELECT * FROM {name} WHERE id = $1");
    let found = a
        .execute_with_params(read(&all), &[QueryParam::Int(1)])
        .await
        .expect("params");
    assert_eq!(found.rows[0][1], json!("a"));
    let slow = ExecQuery {
        statement_timeout_ms: Some(50),
        ..read("SELECT pg_sleep(1)")
    };
    assert!(matches!(a.execute(slow).await, Err(ExecError::Timeout)));

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
        .unwrap_or_else(|err| panic!("{detail:?}: {err:?}"));
    }
    a.sample(SampleQuery {
        schema: Identifier::parse("public").unwrap(),
        table: Identifier::parse(&name).unwrap(),
        statement_timeout_ms: None,
        row_limit: 1,
        request_id: id(),
    })
    .await
    .expect("sample");
    a.table_stats(TableStatsQuery {
        schema: "public",
        table: Some(&name),
        statement_timeout_ms: None,
        row_limit: 1,
        request_id: id(),
    })
    .await
    .expect("table_stats");
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
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let victim = statement("SELECT pg_sleep(5)", access);
        let request_id = victim.request_id;
        let (cancelled, ()) = tokio::join!(a.execute(victim), async {
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                a.db_activity(ActivityQuery {
                    statement_timeout_ms: None,
                    row_limit: 10,
                    request_id: id(),
                })
                .await
                .expect("db_activity");
                if a.cancel_request(request_id).await.expect("cancel") {
                    return;
                }
            }
            panic!("never cancelled");
        });
        assert!(
            matches!(cancelled, Err(ExecError::Cancelled)),
            "{cancelled:?}"
        );
    }

    // Dropped wherever it stands, a later point each time.
    for at in 0..60u64 {
        let sql = if at % 2 == 0 {
            "SELECT e.*, pg_sleep(0.02) FROM pg_class e LIMIT 3"
        } else {
            "SELECT ev_action FROM pg_rewrite LIMIT 2"
        };
        let cut = Duration::from_micros(150 * at);
        // Cut short or done first: a drop before it must never fail it.
        if let Ok(outcome) = tokio::time::timeout(cut, a.execute(read(sql))).await {
            outcome.unwrap_or_else(|err| panic!("after a drop: {sql}: {err:?}"));
        }
    }
    let dropped = a.execute(read("SELECT pg_sleep(5)"));
    let dropped = tokio::time::timeout(Duration::from_millis(300), dropped).await;
    assert!(dropped.is_err(), "{dropped:?}");

    // The backend killed under the statement.
    let victim = read("SELECT pg_sleep(5)");
    let tag = format!("dbmcp-{}-%", victim.request_id.simple());
    let (killed, ()) = tokio::join!(a.execute(victim), async {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let killed: Vec<bool> = sqlx::query_scalar(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE application_name LIKE $1 AND query LIKE '%pg_sleep%'",
            )
            .bind(&tag)
            .fetch_all(&owner)
            .await
            .expect("terminate");
            if killed.contains(&true) {
                return;
            }
        }
        panic!("never killed");
    });
    assert!(matches!(killed, Err(ExecError::Unavailable)), "{killed:?}");
    let recovered = a.execute(read("SELECT 1")).await.expect("recovered");
    assert_eq!(recovered.rows, vec![vec![json!(1)]]);

    detached
        .drain(Duration::from_secs(5))
        .await
        .expect("drop cancels finish");
    run(
        &owner,
        format!("DROP TABLE {name}; DROP TYPE {name}_c; DROP TYPE {name}_e; DROP DOMAIN {name}_d"),
    )
    .await;
    let seen = wire.take();
    // Both routes to the text cast were on the wire, up to the cast itself.
    for route in [
        "DECLARE dbmcp_columns",
        "q.c1::text AS \"relacl\"",
        "q.c1::text AS \"ev_action\"",
        "SELECT * FROM",
        "UPDATE",
    ] {
        assert!(
            seen.parses.iter().any(|text| text.contains(route)),
            "nothing parsed holds {route}"
        );
    }
    assert!(
        seen.violations.is_empty(),
        "{} violations, first: {:?}",
        seen.violations.len(),
        &seen.violations[..seen.violations.len().min(5)]
    );
}
