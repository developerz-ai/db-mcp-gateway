//! The Redis timeout path: Redis has no per-command server timeout, so the
//! gateway budget is client-side. `CLIENT PAUSE` from the admin side stalls
//! the server; the command must time out, and its connection must be
//! discarded so the next command — on a one-connection pool — gets its own
//! reply. Serial: `CLIENT PAUSE ALL` stalls every client of the server.

use std::collections::HashSet;
use std::future::Future;
use std::num::NonZeroU32;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::common::redis_target::{
    DB_INDEX, Flavor, adapter, admin, admin_cmd, delete_keys, unique_key,
};
use db_mcp_gateway::exec::{Access, DbAdapter, ExecError, ExecQuery, PoolSizing};
use redis::aio::MultiplexedConnection;
use serde_json::json;

const PAUSE_MS: u64 = 800;

fn query(argv: &str, statement_timeout_ms: Option<u32>) -> ExecQuery<'_> {
    ExecQuery {
        sql: argv,
        binds: &[],
        statement_timeout_ms,
        row_limit: 10,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: uuid::Uuid::new_v4(),
    }
}

/// Ids of the server's connections on [`DB_INDEX`], the admin side's own
/// excluded. `CLIENT LIST` has `id=` and `db=` on Redis and Dragonfly alike.
async fn gateway_connection_ids(side: &mut MultiplexedConnection) -> HashSet<String> {
    let own = match admin_cmd(side, &["CLIENT", "ID"]).await {
        redis::Value::Int(id) => id.to_string(),
        other => panic!("CLIENT ID: {other:?}"),
    };
    let listing = match admin_cmd(side, &["CLIENT", "LIST"]).await {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes).expect("UTF-8 listing"),
        redis::Value::VerbatimString { text, .. } => text,
        other => panic!("CLIENT LIST: {other:?}"),
    };
    let on_db = format!("db={DB_INDEX}");
    listing
        .lines()
        .filter(|line| line.split(' ').any(|field| field == on_db))
        .filter_map(|line| line.split(' ').find_map(|f| f.strip_prefix("id=")))
        .filter(|id| *id != own)
        .map(str::to_string)
        .collect()
}

#[tokio::test]
#[serial_test::serial(world)]
async fn a_stalled_server_times_out_and_the_connection_is_discarded() {
    for flavor in Flavor::ALL {
        let one = PoolSizing {
            max_connections: NonZeroU32::MIN.get(),
            ..PoolSizing::default()
        };
        let a = adapter(flavor, one).await;
        let mut side = admin(flavor).await;
        let (first, second) = (unique_key("t1"), unique_key("t2"));
        admin_cmd(&mut side, &["SET", &first, "first"]).await;
        admin_cmd(&mut side, &["SET", &second, "second"]).await;
        // Warm the single pooled connection so the stalled command reuses it.
        let warm = a
            .execute(query(&format!(r#"["GET","{first}"]"#), None))
            .await
            .expect("warm-up read");
        assert_eq!(warm.rows, vec![vec![json!("first")]]);
        let before = gateway_connection_ids(&mut side).await;

        let pause = PAUSE_MS.to_string();
        admin_cmd(&mut side, &["CLIENT", "PAUSE", &pause, "ALL"]).await;
        let started = Instant::now();
        let stalled = a
            .execute(query(&format!(r#"["GET","{first}"]"#), Some(200)))
            .await;
        let waited = started.elapsed();
        assert!(
            matches!(stalled, Err(ExecError::Timeout)),
            "{}: {stalled:?}",
            flavor.name()
        );
        assert!(waited < Duration::from_millis(PAUSE_MS), "{waited:?}");

        // Sent while the server is still paused: it waits out the rest of the
        // pause on its own. Had the stalled connection gone back to the pool,
        // its late reply ("first") could answer this read; a fresh one does.
        let next = a
            .execute(query(&format!(r#"["GET","{second}"]"#), None))
            .await
            .unwrap_or_else(|err| panic!("{}: next read: {err:?}", flavor.name()));
        assert_eq!(next.rows, vec![vec![json!("second")]], "{}", flavor.name());
        // The one-connection pool opened a new connection for this read: the
        // stalled one was not handed back.
        let after = gateway_connection_ids(&mut side).await;
        assert!(
            after.difference(&before).next().is_some(),
            "{}: no fresh connection (before {before:?}, after {after:?})",
            flavor.name()
        );
        delete_keys(&mut side, &[&first, &second]).await;
    }
}

/// A saturated pool is `unavailable` after the acquire bound, not a
/// `timeout` of the waiting caller's command — the Postgres adapter's
/// contract. The only connection is pinned by a command the paused server
/// cannot answer yet; it completes once the pause ends. The bound is cut
/// from the production 5 s to [`ACQUIRE`]; the waiter's budget stays below
/// it, so a budget that wrongly covered the wait would fire first.
#[tokio::test]
#[serial_test::serial(world)]
async fn a_saturated_pool_is_unavailable_not_timeout() {
    const HOLD_MS: u64 = 1_500;
    const ACQUIRE: Duration = Duration::from_millis(500);
    for flavor in Flavor::ALL {
        let one = PoolSizing {
            max_connections: NonZeroU32::MIN.get(),
            ..PoolSizing::default()
        };
        let a = adapter(flavor, one).await.with_acquire_timeout(ACQUIRE);
        let mut side = admin(flavor).await;
        let key = unique_key("held");
        admin_cmd(&mut side, &["SET", &key, "held"]).await;
        a.execute(query(r#"["DBSIZE"]"#, None))
            .await
            .expect("warm the one connection");

        admin_cmd(&mut side, &["CLIENT", "PAUSE", &HOLD_MS.to_string(), "ALL"]).await;
        let argv = format!(r#"["GET","{key}"]"#);
        let mut holder = std::pin::pin!(a.execute(query(&argv, None)));
        // One poll leases the only connection and sends the command, which the
        // paused server leaves unanswered: the pool is saturated from here on.
        let polled = std::future::poll_fn(|cx| Poll::Ready(holder.as_mut().poll(cx))).await;
        assert!(
            polled.is_pending(),
            "{}: paused server answered",
            flavor.name()
        );
        let started = Instant::now();
        let waiting = a.execute(query(r#"["DBSIZE"]"#, Some(200))).await;
        let waited = started.elapsed();
        assert!(
            matches!(waiting, Err(ExecError::Unavailable)),
            "{}: {waiting:?}",
            flavor.name()
        );
        assert!(waited >= ACQUIRE, "{waited:?}: the acquire bound");
        let held = holder.await.map(|r| r.rows);
        assert_eq!(
            held.expect("holder read"),
            vec![vec![json!("held")]],
            "{}",
            flavor.name()
        );
        delete_keys(&mut side, &[&key]).await;
    }
}
