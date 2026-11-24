//! Real-mongo tests for what the adapter answers, not just that it answers:
//! non-finite doubles render as Extended JSON (never a fabricated `null`), a
//! role missing a privilege is a permission refusal (never a syntax error),
//! and a saturated pool is `unavailable` (never the caller's `timeout`).
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mongodb::bson::{Document, doc};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::common::mongo_target::{
    TARGET_DB, TARGET_HOST, TARGET_PORT, adapter, database, drop_collection, server, side_client,
    unique_collection,
};
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::Password;
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, ExecResult, MongoAdapter, PoolSizing,
};

async fn run(
    a: &MongoAdapter,
    sql: &str,
    statement_timeout_ms: Option<u32>,
) -> Result<ExecResult, ExecError> {
    a.execute(ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms,
        row_limit: 100,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    })
    .await
}

async fn insert(collection: &str, documents: Vec<Document>) {
    side_client()
        .database(TARGET_DB)
        .run_command(doc! { "insert": collection, "documents": documents })
        .await
        .expect("seed insert");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn non_finite_doubles_render_as_extended_json() {
    let a = adapter("mongo").await;
    let coll = unique_collection("mongodbl");
    insert(
        &coll,
        vec![doc! {
            "_id": 1,
            "nan": f64::NAN,
            "inf": f64::INFINITY,
            "ninf": f64::NEG_INFINITY,
            "nested": [f64::NAN, 2.5],
            "nothing": null,
        }],
    )
    .await;

    let find = run(&a, &format!(r#"{{"find":"{coll}"}}"#), None).await;
    let distinct = run(&a, &format!(r#"{{"distinct":"{coll}","key":"inf"}}"#), None).await;
    drop_collection(&side_client(), &coll).await;

    let find = find.expect("find");
    assert_eq!(
        find.rows,
        vec![vec![json!({
            "_id": 1,
            "nan": { "$numberDouble": "NaN" },
            "inf": { "$numberDouble": "Infinity" },
            "ninf": { "$numberDouble": "-Infinity" },
            "nested": [{ "$numberDouble": "NaN" }, 2.5],
            "nothing": null,
        })]]
    );
    assert_eq!(
        distinct.expect("distinct").rows,
        vec![vec![json!({ "$numberDouble": "Infinity" })]]
    );
}

/// A user whose role may `find` on `allowed` only, in [`TARGET_DB`].
struct NarrowUser {
    user: String,
    role: String,
}

impl NarrowUser {
    const PASSWORD: &str = "narrow-dev-only";

    async fn create(allowed: &str) -> Self {
        let suffix = Uuid::new_v4().simple().to_string();
        let (user, role) = (format!("gw_narrow_{suffix}"), format!("gw_find_{suffix}"));
        let db = side_client().database(TARGET_DB);
        db.run_command(doc! {
            "createRole": &role,
            "privileges": [{ "resource": { "db": TARGET_DB, "collection": allowed }, "actions": ["find"] }],
            "roles": [],
        })
        .await
        .expect("createRole");
        db.run_command(doc! { "createUser": &user, "pwd": Self::PASSWORD, "roles": [&role] })
            .await
            .expect("createUser");
        Self { user, role }
    }

    async fn drop(self) {
        let db = side_client().database(TARGET_DB);
        let _ = db.run_command(doc! { "dropUser": &self.user }).await;
        let _ = db.run_command(doc! { "dropRole": &self.role }).await;
    }
}

/// Mongo's `Unauthorized` (code 13) is the role lacking a privilege — the
/// agent's query is fine. It carries the code and the gateway's wording,
/// never the server's message (which echoes the command).
#[tokio::test]
#[serial_test::parallel(world)]
async fn unauthorized_is_a_permission_refusal_not_a_syntax_error() {
    let allowed = unique_collection("mongoauthz");
    let denied = unique_collection("mongoauthz");
    let narrow = NarrowUser::create(&allowed).await;
    let mut db = database();
    db.role = narrow.user.clone();
    db.password = Password::Literal(NarrowUser::PASSWORD.into());
    db.auth_database = None;
    let a = MongoAdapter::open(
        &server("mongo"),
        &db,
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("client builds");

    let ok = run(&a, &format!(r#"{{"find":"{allowed}"}}"#), None).await;
    let refused = run(
        &a,
        &format!(r#"{{"find":"{denied}","filter":{{"secret":"v"}}}}"#),
        None,
    )
    .await;
    narrow.drop().await;

    assert!(ok.is_ok(), "{ok:?}");
    let Err(ExecError::Rejected(rejection)) = refused else {
        panic!("expected a rejection, got {refused:?}");
    };
    assert_eq!(rejection.sqlstate(), "13");
    assert_eq!(rejection.to_string(), "13 not authorized");
}

/// A TCP forwarder to the target that swallows the first client write
/// carrying `marker` and then holds that connection silent: the command
/// holding it never gets a reply, however fast the server would have been.
/// Resolves `swallowed` once that write has arrived.
async fn stalling_proxy(marker: String) -> (u16, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let port = listener.local_addr().expect("proxy addr").port();
    let (swallowed_tx, swallowed) = tokio::sync::oneshot::channel();
    let swallowed_tx = Arc::new(std::sync::Mutex::new(Some(swallowed_tx)));
    let marker = Arc::new(marker.into_bytes());
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(forward(client, marker.clone(), swallowed_tx.clone()));
        }
    });
    (port, swallowed)
}

type Signal = Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>;

async fn forward(mut client: TcpStream, marker: Arc<Vec<u8>>, swallowed: Signal) {
    let Ok(mut server) = TcpStream::connect((TARGET_HOST, TARGET_PORT)).await else {
        return;
    };
    let (mut up, mut down) = ([0u8; 16 * 1024], [0u8; 16 * 1024]);
    let mut scan = MarkerScan::new(&marker);
    loop {
        tokio::select! {
            read = client.read(&mut up) => {
                let Ok(n @ 1..) = read else { return };
                if scan.feed(&up[..n]) {
                    if let Some(tx) = swallowed.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    // Keep both sockets open and silent until the test ends.
                    return std::future::pending().await;
                }
                if server.write_all(&up[..n]).await.is_err() {
                    return;
                }
            }
            read = server.read(&mut down) => {
                let Ok(n @ 1..) = read else { return };
                if client.write_all(&down[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Finds the marker in a byte stream even when TCP splits it across reads.
struct MarkerScan<'a> {
    marker: &'a [u8],
    tail: Vec<u8>,
}

impl<'a> MarkerScan<'a> {
    fn new(marker: &'a [u8]) -> Self {
        Self {
            marker,
            tail: Vec::new(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> bool {
        self.tail.extend_from_slice(bytes);
        let found = self
            .tail
            .windows(self.marker.len())
            .any(|w| w == self.marker);
        let keep = self.tail.len().saturating_sub(self.marker.len() - 1);
        self.tail.drain(..keep);
        found
    }
}

#[test]
#[serial_test::parallel(world)]
fn marker_scan_matches_across_read_boundaries() {
    let mut scan = MarkerScan::new(b"mongosat_1");
    assert!(!scan.feed(b"\x02count\0mongo"));
    assert!(scan.feed(b"sat_1\0"));
    assert!(!MarkerScan::new(b"mongosat_1").feed(b"count other"));
}

/// The pool's only connection is held by a command whose reply never comes
/// (a proxy swallows it): the next caller waits outside its statement budget
/// and gets `unavailable` after the 5 s acquire wait — not a `timeout` for a
/// command that never started. The held command ends as `timeout`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_saturated_pool_is_unavailable_not_timeout() {
    let stalled = unique_collection("mongosat");
    let (port, swallowed) = stalling_proxy(stalled.clone()).await;
    let sizing = PoolSizing {
        max_connections: 1,
        ..PoolSizing::default()
    };
    let mut via_proxy = server("mongo-sat");
    via_proxy.host = "127.0.0.1".to_string();
    via_proxy.port = port;
    let a = MongoAdapter::open(&via_proxy, &database(), sizing, DetachedTasks::new())
        .await
        .expect("client builds");
    let held = format!(r#"{{"count":"{stalled}","query":{{}}}}"#);
    let count = format!(
        r#"{{"count":"{}","query":{{}}}}"#,
        unique_collection("mongosatwait")
    );

    let held_call = run(&a, &held, Some(10_000));
    let waiting_call = async {
        // The command is written only once its call holds the connection.
        // Bounded: the accept loop keeps the sender alive, so a missed
        // marker would otherwise wait forever.
        tokio::time::timeout(Duration::from_secs(10), swallowed)
            .await
            .expect("the held command reaches the proxy within 10 s")
            .expect("the proxy signals");
        let started = Instant::now();
        (run(&a, &count, Some(1_000)).await, started.elapsed())
    };
    let (held_result, (waited, elapsed)) = tokio::join!(held_call, waiting_call);

    assert!(
        matches!(held_result, Err(ExecError::Timeout)),
        "{held_result:?}"
    );
    assert!(matches!(waited, Err(ExecError::Unavailable)), "{waited:?}");
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(8),
        "waited {elapsed:?}"
    );
}
