//! Real-mongo tests for what the adapter answers, not just that it answers:
//! non-finite doubles render as Extended JSON (never a fabricated `null`), a
//! role missing a privilege is a permission refusal (never a syntax error),
//! a saturated pool is `unavailable` (never the caller's `timeout`), and a
//! call's server-side cleanup never takes the next call's connection.
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mongodb::bson::{Bson, Document, JavaScriptCodeWithScope, doc};
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
            "code": Bson::JavaScriptCodeWithScope(JavaScriptCodeWithScope {
                code: "x".into(),
                scope: doc! { "nan": f64::NAN, "list": [f64::NEG_INFINITY, 2.5] },
            }),
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
            "code": {
                "$code": "x",
                "$scope": {
                    "nan": { "$numberDouble": "NaN" },
                    "list": [{ "$numberDouble": "-Infinity" }, 2.5],
                },
            },
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

/// A TCP forwarder to the target that swallows the first client write on a
/// connection carrying one of `markers` and then holds that connection
/// silent: the command holding it never gets a reply, however fast the server
/// would have been. `swallowed` gets one message per swallowed write.
async fn stalling_proxy(markers: Vec<String>) -> (u16, Swallowed) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let port = listener.local_addr().expect("proxy addr").port();
    let (swallowed_tx, swallowed) = tokio::sync::mpsc::unbounded_channel();
    let markers = Arc::new(markers);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(forward(client, markers.clone(), swallowed_tx.clone()));
        }
    });
    (port, swallowed)
}

type Swallowed = tokio::sync::mpsc::UnboundedReceiver<String>;
type Signal = tokio::sync::mpsc::UnboundedSender<String>;

/// The next swallowed marker. Bounded: the accept loop keeps the sender
/// alive, so a missed marker would otherwise wait forever.
async fn next_swallowed(swallowed: &mut Swallowed) -> String {
    tokio::time::timeout(Duration::from_secs(10), swallowed.recv())
        .await
        .expect("the command reaches the proxy within 10 s")
        .expect("the proxy signals")
}

/// An adapter on the target through the proxy at `port`, with a pool of one.
async fn pool_of_one(port: u16, detached: DetachedTasks) -> MongoAdapter {
    let sizing = PoolSizing {
        max_connections: 1,
        ..PoolSizing::default()
    };
    let mut via_proxy = server("mongo-one");
    via_proxy.host = "127.0.0.1".to_string();
    via_proxy.port = port;
    MongoAdapter::open(&via_proxy, &database(), sizing, detached)
        .await
        .expect("client builds")
}

async fn forward(mut client: TcpStream, markers: Arc<Vec<String>>, swallowed: Signal) {
    let Ok(mut server) = TcpStream::connect((TARGET_HOST, TARGET_PORT)).await else {
        return;
    };
    let (mut up, mut down) = ([0u8; 16 * 1024], [0u8; 16 * 1024]);
    let mut scans: Vec<_> = markers
        .iter()
        .map(|marker| (marker, MarkerScan::new(marker.as_bytes())))
        .collect();
    loop {
        tokio::select! {
            read = client.read(&mut up) => {
                let Ok(n @ 1..) = read else { return };
                let hit = scans
                    .iter_mut()
                    .filter_map(|(marker, scan)| scan.feed(&up[..n]).then_some(marker.as_str()))
                    .next();
                if let Some(marker) = hit {
                    let _ = swallowed.send(marker.to_owned());
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
    let (port, mut swallowed) = stalling_proxy(vec![stalled.clone()]).await;
    let a = pool_of_one(port, DetachedTasks::new()).await;
    let held = format!(r#"{{"count":"{stalled}","query":{{}}}}"#);
    let count = format!(
        r#"{{"count":"{}","query":{{}}}}"#,
        unique_collection("mongosatwait")
    );

    let held_call = run(&a, &held, Some(10_000));
    let waiting_call = async {
        // The command is written only once its call holds the connection.
        next_swallowed(&mut swallowed).await;
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

/// A row cap that cuts a cursor leaves none open on the server: the driver
/// closes an open one with a `killCursors` nothing reserves a connection
/// for, and a stuck one would hold the pool's only connection through the
/// next call's budget.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_row_cap_cut_leaves_no_cursor_to_clean_up() {
    let coll = unique_collection("mongocut");
    insert(&coll, (0..300).map(|i| doc! { "i": i }).collect()).await;
    let (port, mut swallowed) = stalling_proxy(vec!["killCursors".to_owned()]).await;
    let a = pool_of_one(port, DetachedTasks::new()).await;
    let find = format!(r#"{{"find":"{coll}"}}"#);
    let sorted = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$group":{{"_id":"$i"}}}},{{"$sort":{{"_id":1}}}}],"cursor":{{}}}}"#
    );
    let plain = format!(r#"{{"aggregate":"{coll}","pipeline":[],"cursor":{{}}}}"#);

    let mut results = Vec::new();
    for sql in [&find, &sorted, &plain, &find] {
        results.push(run(&a, sql, Some(1_000)).await);
        // Time for the driver's detached cleanup, were there one, to start.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop_collection(&side_client(), &coll).await;

    assert!(swallowed.try_recv().is_err(), "killCursors was sent");
    for result in results {
        let result = result.expect("each call runs inside its own budget");
        assert_eq!(result.rows.len(), 100);
        assert!(result.truncated);
    }
}

/// A timed-out call's `currentOp` / `killOp` runs on the call's own
/// reservation, so a stuck one delays the next caller's acquire — outside its
/// statement budget, and only up to the cleanup bound — never the command.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_stuck_cancel_never_costs_the_next_call_its_budget() {
    let stalled = unique_collection("mongostuck");
    let (port, mut swallowed) = stalling_proxy(vec![stalled.clone(), "currentOp".to_owned()]).await;
    let detached = DetachedTasks::new();
    let a = pool_of_one(port, detached.clone()).await;

    let held = run(
        &a,
        &format!(r#"{{"count":"{stalled}","query":{{}}}}"#),
        Some(200),
    )
    .await;
    assert!(matches!(held, Err(ExecError::Timeout)), "{held:?}");
    assert_eq!(next_swallowed(&mut swallowed).await, stalled);
    assert_eq!(next_swallowed(&mut swallowed).await, "currentOp");

    let next = format!(
        r#"{{"count":"{}","query":{{}}}}"#,
        unique_collection("mongostucknext")
    );
    let started = Instant::now();
    let next = run(&a, &next, Some(1_000)).await;
    let elapsed = started.elapsed();
    assert!(next.is_ok(), "{next:?} after {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "waited {elapsed:?}");
    detached
        .drain(Duration::from_secs(2))
        .await
        .expect("the stuck cancel was bounded");
}
