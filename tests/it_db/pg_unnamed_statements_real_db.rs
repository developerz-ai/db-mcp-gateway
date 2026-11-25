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
use sqlx::postgres::{PgConnectOptions, PgDatabaseError, PgPoolOptions, PgSslMode};
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
                    assert_eq!(found.rows.len(), 1, "{found:?}");
                    assert_eq!(found.columns, ["id", "e", "es", "c", "d"]);
                    assert_eq!(found.rows[0][..2], [json!(1), json!("a")], "{found:?}");
                    assert_eq!(found.rows[0][2], json!(["a", "b"]), "{found:?}");
                    assert_eq!(found.rows[0][4], json!(1), "{found:?}");
                    let none = reader
                        .execute(read(&format!("SELECT * FROM {name} WHERE false")))
                        .await
                        .unwrap_or_else(|err| panic!("zero rows {round}: {err:?}"));
                    assert!(none.rows.is_empty());
                    assert_eq!(none.columns, found.columns);
                }
                let sql = format!("UPDATE {name} SET e = 'b' RETURNING e, es, c, d");
                let written = writable_adapter()
                    .await
                    .execute(statement(&sql, Access::ReadWrite))
                    .await
                    .unwrap_or_else(|err| panic!("write: {err:?}"));
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
                let mut widths = Vec::new();
                while !done.load(Ordering::Relaxed) {
                    match adapter.execute(read(&sql)).await {
                        Ok(result) => {
                            let columns = result.columns.len();
                            let last = widths.last().copied().unwrap_or(0);
                            assert!(columns >= last, "{columns} columns after {last}");
                            if columns > last {
                                widths.push(columns);
                            }
                            let rows = if at == 0 { 0 } else { 2 };
                            assert_eq!(result.rows.len(), rows, "{result:?}");
                            assert!(result.rows.iter().all(|row| row.len() == columns));
                        }
                        Err(err) => failures.push(format!("{err:?}")),
                    }
                }
                (failures, widths)
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
        let (failures, widths) = outcome.expect("reader");
        assert_eq!(failures, Vec::<String>::new());
        // Reading before, between and after the changes, not around them.
        assert!(widths.len() > 2, "saw only {widths:?} columns");
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
        let mut frames = Vec::new();
        loop {
            let head = usize::from(!self.startup_pending);
            let Some(len) = self.pending.get(head..head + 4) else {
                return frames;
            };
            let end = head + u32::from_be_bytes(len.try_into().unwrap()) as usize;
            if self.pending.len() < end {
                return frames;
            }
            let raw: Vec<u8> = self.pending.drain(..end).collect();
            let kind = (!self.startup_pending).then(|| raw[0]);
            self.startup_pending = false;
            frames.push(Frame { kind, raw });
        }
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
    /// The text of every Parse.
    parses: Vec<String>,
    /// Every simple query.
    queries: Vec<String>,
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

    fn parsed(&self, needle: &str) -> bool {
        let seen = self.seen.lock().unwrap();
        seen.parses.iter().any(|text| text.contains(needle))
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
    fn client(&mut self, session: &mut Session, frame: &Frame) {
        let body = frame.body();
        let text = String::from_utf8_lossy(body);
        let Some(kind) = frame.kind else {
            return;
        };
        // Parse starts with the statement's name; Bind with the portal's,
        // then the statement's; Describe and Close with which of the two
        // they are for, then its name.
        let name = match kind {
            // A simple query and a Sync are each answered with the state.
            b'Q' | b'S' => {
                session.unanswered += 1;
                if kind == b'Q' {
                    self.queries.push(text.trim_end_matches('\0').to_string());
                }
                return;
            }
            b'P' => {
                self.parses.push(text.to_string());
                body.split(|b| *b == 0).next()
            }
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
    assert_eq!(seen.queries, ["BEGIN"]);
    assert_eq!(seen.parses.len(), 1);

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
        ("SELECT 1 / 0, ev_action FROM pg_rewrite LIMIT 1", "22012"),
    ] {
        assert_refused(a.execute(read(sql)).await, sqlstate, sql);
    }
    // The near-miss lookup behind an undefined name gives up, silently, after
    // 200 ms: a busy target gets another chance to be asked.
    for (sql, sqlstate, lookup) in [
        (nope.as_str(), "42703", "quote_ident(a.attname)"),
        (
            "SELECT * FROM dbmcp_no_such_table",
            "42P01",
            "quote_ident(c.relname)",
        ),
    ] {
        for _ in 0..20 {
            assert_refused(a.execute(read(sql)).await, sqlstate, sql);
            if wire.parsed(lookup) {
                break;
            }
        }
        assert!(wire.parsed(lookup), "{sql}: no near-miss lookup");
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
        let victim = statement("SELECT pg_sleep(5)", access);
        let request_id = victim.request_id;
        let (cancelled, ()) = tokio::join!(a.execute(victim), async {
            running(&owner, request_id).await;
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
        assert!(
            matches!(cancelled, Err(ExecError::Cancelled)),
            "{cancelled:?}"
        );
        by_request.push(request_id);
    }

    // Dropped wherever it stands, a later point each time, up to its end.
    let drop_read = "SELECT e.relname, pg_sleep(0.02) FROM pg_class e LIMIT 1";
    let drop_cast = "SELECT ev_action FROM pg_rewrite LIMIT 2";
    let mut dropped_ids = Vec::new();
    for sql in [drop_read, drop_cast] {
        let started = std::time::Instant::now();
        a.execute(read(sql)).await.expect("undisturbed");
        let whole = started.elapsed();
        for at in 0..30 {
            let victim = read(sql);
            let request_id = victim.request_id;
            // Cut short or done first: a drop before it must never fail it.
            match tokio::time::timeout(whole * at / 28, a.execute(victim)).await {
                Ok(outcome) => {
                    outcome.unwrap_or_else(|err| panic!("after a drop: {sql}: {err:?}"));
                }
                Err(_elapsed) => dropped_ids.push(request_id),
            }
        }
    }

    // Dropped while its backend runs it: the backend is cancelled.
    let victim = read("SELECT pg_sleep(8)");
    let request_id = victim.request_id;
    let dropped_tag = tokio::select! {
        outcome = a.execute(victim) => panic!("pg_sleep(8) ended: {outcome:?}"),
        tag = running(&owner, request_id) => tag,
    };
    let mut still = true;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        still = backend_tag(&owner, request_id).await.is_some();
        if !still {
            break;
        }
    }
    assert!(!still, "the dropped call's backend kept running");

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
        assert!(
            seen.parses.iter().any(|text| text.contains(route)),
            "nothing parsed holds {route}"
        );
    }
    // Every kind of cancel reached the target, as a simple query.
    let cancels: Vec<&String> = seen
        .queries
        .iter()
        .filter(|query| query.contains("pg_cancel_backend"))
        .collect();
    let cancelled = |needle: &str| cancels.iter().any(|query| query.contains(needle));
    let tagged = |id: &Uuid| format!("application_name = 'dbmcp-{}-", id.simple());
    assert!(
        cancelled(&format!("application_name = '{dropped_tag}'")),
        "{dropped_tag}"
    );
    assert!(cancelled(&tagged(&capped_id)), "the row cap");
    assert!(
        dropped_ids.iter().any(|id| cancelled(&tagged(id))),
        "none of {} drops",
        dropped_ids.len()
    );
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

/// The tag of the backend sleeping for `request_id`, waited for.
async fn running(owner: &sqlx::PgPool, request_id: Uuid) -> String {
    for _ in 0..80 {
        if let Some(tag) = backend_tag(owner, request_id).await {
            return tag;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{request_id} never ran on the target");
}

async fn backend_tag(owner: &sqlx::PgPool, request_id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT application_name FROM pg_stat_activity WHERE state = 'active' \
         AND application_name LIKE $1 AND query LIKE 'SELECT pg_sleep%'",
    )
    .bind(format!("dbmcp-{}-%", request_id.simple()))
    .fetch_optional(owner)
    .await
    .expect("pg_stat_activity")
}
