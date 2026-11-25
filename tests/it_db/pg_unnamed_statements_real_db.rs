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
use db_mcp_gateway::exec::{
    Access, ActivityQuery, DbAdapter, ExecError, ExecQuery, ExplainQuery, GuardedSql, Identifier,
    PgAdapter, PoolSizing, QueryParam, SampleQuery, SchemaDetail, SchemaQuery, TableStatsQuery,
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
/// no read fails and every row is as wide as its header.
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
    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|at| {
            let (adapter, done, table) = (adapter.clone(), done.clone(), table.clone());
            tokio::spawn(async move {
                let filter = if at == 0 { "WHERE id < 0" } else { "" };
                let sql = format!("SELECT * FROM {table} {filter}");
                let mut failures = Vec::new();
                while !done.load(Ordering::Relaxed) {
                    match adapter.execute(read(&sql)).await {
                        Ok(result) => assert!(
                            result.rows.iter().all(|r| r.len() == result.columns.len()),
                            "{result:?}"
                        ),
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
    done.store(true, Ordering::Relaxed);
    let outcomes = futures::future::join_all(readers).await;
    run(&owner, format!("DROP TABLE {table}")).await;
    for outcome in outcomes {
        assert_eq!(outcome.expect("reader"), Vec::<String>::new());
    }
    assert_eq!(last.expect("last read").columns.len(), 21);
}

/// "cached plan must not change result type", provoked inside one statement:
/// a SQL-level prepared statement whose table changes under it with the
/// search path. Nothing in the caller's SQL is there to fix — unlike any
/// other `0A000`, raised by a function or by the server itself.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_stale_plan_is_retryable_and_no_other_0a000_is() {
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
    let stale = adapter.execute(read(&format!("SELECT {name}()"))).await;
    let raised = adapter
        .execute(read(&format!("SELECT {name}_raise()")))
        .await;
    let unsupported = adapter
        .execute(read("SELECT 1 UNION SELECT 2 FOR UPDATE"))
        .await;
    run(
        &owner,
        format!(
            "DROP FUNCTION {name}(); DROP FUNCTION {name}_raise(); \
             DROP SCHEMA {name}_a CASCADE; DROP SCHEMA {name}_b CASCADE"
        ),
    )
    .await;
    assert!(matches!(stale, Err(ExecError::Unavailable)), "{stale:?}");
    for other in [raised, unsupported] {
        let Err(ExecError::Rejected(rejection)) = other else {
            panic!("{other:?}")
        };
        assert_eq!(rejection.sqlstate(), "0A000");
    }
}

/// A TCP forwarder to the target that reads both directions of every
/// connection and keeps what a transaction-mode pooler could not serve.
struct WireRecorder {
    port: u16,
    seen: Arc<Mutex<Seen>>,
}

#[derive(Default)]
struct Seen {
    parses: usize,
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
            self.parses += 1;
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
    assert!(seen.parses > 0);
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
    for sql in [
        "SELECT 1 / 0".to_string(),
        format!("SELECT nope FROM {name}"),
        format!("SELECT * FROM {name}"),
        format!("SELECT e FROM {name} WHERE false"),
        "SELECT relacl FROM pg_class LIMIT 1".to_string(),
        "SELECT ev_action FROM pg_rewrite LIMIT 1".to_string(),
        "SELECT 1 / 0, ev_action FROM pg_rewrite LIMIT 1".to_string(),
        "SELECT generate_series(1, 100000)".to_string(),
        "SELECT * FROM dbmcp_no_such_table".to_string(),
    ] {
        let _ = a.execute(read(&sql)).await;
    }
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
        a.execute(ExecQuery {
            dry_run,
            ..statement(&update, Access::ReadWrite)
        })
        .await
        .expect("write");
    }
    let refused = format!("INSERT INTO {name} (id) VALUES (1)");
    assert!(
        a.execute(statement(&refused, Access::ReadWrite))
            .await
            .is_err()
    );

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
        let _ = tokio::time::timeout(cut, a.execute(read(sql))).await;
    }
    let dropped = a.execute(read("SELECT pg_sleep(5)"));
    let _ = tokio::time::timeout(Duration::from_millis(300), dropped).await;

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
    a.execute(read("SELECT 1")).await.expect("recovered");

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
    assert!(seen.parses > 100, "recorded {} parses", seen.parses);
    assert!(
        seen.violations.is_empty(),
        "{} violations, first: {:?}",
        seen.violations.len(),
        &seen.violations[..seen.violations.len().min(5)]
    );
}
