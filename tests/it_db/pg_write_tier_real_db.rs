//! The write tier across replicas and under broken credentials, and the
//! connection a failed truncation rollback leaves behind.
//!
//! - Another replica's write is listed by `db_activity` and stopped by
//!   `cancel_request` on a replica that never wrote (two adapters on one
//!   target stand in for two gateway processes).
//! - A write credential that does not resolve, or that the target refuses,
//!   fails writes only: reads keep working and the adapter is not stale.
//! - A truncated read whose rollback fails leaves no reused connection.
//! - `db_activity` listings in flight never hold back the cancel of a write:
//!   they run on the query pool, the cancel pool stays the cancels'.
//!
//! Target: `target-db` (`bin/dev up`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::Password;
use db_mcp_gateway::exec::{
    Access, ActivityQuery, DbAdapter, ExecError, ExecQuery, PgAdapter, PoolSizing,
};
use serde_json::json;
use uuid::Uuid;

use crate::common::pg_target::{
    ensure_read_role, owner_url, server, single_connection_adapter, writable_adapter,
    writable_database,
};

fn query(sql: &str, access: Access, row_limit: u32) -> ExecQuery<'_> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: Some(30_000),
        row_limit,
        access,
        dry_run: false,
        request_id: Uuid::new_v4(),
    }
}

fn activity() -> ActivityQuery {
    ActivityQuery {
        statement_timeout_ms: None,
        row_limit: 100,
        request_id: Uuid::new_v4(),
    }
}

/// Whether `adapter`'s `db_activity` lists `request_id` on the write tier,
/// polled for up to five seconds.
async fn lists_write(adapter: &PgAdapter, request_id: Uuid) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let listing = adapter.db_activity(activity()).await.expect("activity");
        let col = |name: &str| listing.columns.iter().position(|c| c == name);
        let (Some(id), Some(pool)) = (col("request_id"), col("pool")) else {
            panic!("activity columns: {:?}", listing.columns)
        };
        if listing
            .rows
            .iter()
            .any(|row| row[id] == json!(request_id.to_string()) && row[pool] == json!("write"))
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_write_on_one_replica_is_listed_and_cancelled_from_another() {
    let writer = Arc::new(writable_adapter().await);
    let other = writable_adapter().await;
    let victim_id = Uuid::new_v4();
    let victim = {
        let writer = Arc::clone(&writer);
        tokio::spawn(async move {
            writer
                .execute(ExecQuery {
                    request_id: victim_id,
                    ..query("SELECT pg_sleep(20)", Access::ReadWrite, 1)
                })
                .await
        })
    };

    assert!(
        lists_write(&other, victim_id).await,
        "the other replica never listed the write"
    );
    assert!(
        other.cancel_request(victim_id).await.expect("cancel runs"),
        "the other replica answered 'already finished' for a running write"
    );
    let outcome = victim.await.expect("victim task");
    assert!(matches!(outcome, Err(ExecError::Cancelled)), "{outcome:?}");
}

async fn adapter_with_write_password(password: Password) -> PgAdapter {
    ensure_read_role().await;
    let database = db_mcp_gateway::config::Database {
        write_password: Some(password),
        ..writable_database()
    };
    PgAdapter::open(
        &server(),
        &database,
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("the read tier opens whatever the write credential")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_broken_write_credential_leaves_the_read_tier_alone() {
    let unresolved =
        adapter_with_write_password(Password::EnvVar("DBMCP_TEST_NEVER_SET_WRITE_PW".into())).await;
    let refused = adapter_with_write_password(Password::Literal("wrong-password".into())).await;

    for (adapter, label) in [(&unresolved, "unresolved"), (&refused, "refused")] {
        let write = adapter
            .execute(query("SELECT 1", Access::ReadWrite, 1))
            .await;
        assert!(
            matches!(
                write,
                Err(ExecError::PasswordUnresolved { .. } | ExecError::Connection)
            ),
            "{label}: {write:?}"
        );
        assert!(
            !adapter.is_stale(),
            "{label}: a write failure evicted the reads"
        );
        let read = adapter
            .execute(query("SELECT 1 AS one", Access::ReadOnly, 1))
            .await
            .unwrap_or_else(|err| panic!("{label}: read after a failed write: {err:?}"));
        assert_eq!(read.rows, vec![vec![json!(1)]], "{label}");
        // Activity still answers, from the read tier.
        adapter
            .db_activity(activity())
            .await
            .unwrap_or_else(|err| panic!("{label}: activity: {err:?}"));
    }
}

/// The backend ends itself after the rows the read keeps: the truncation's
/// rollback then fails on a dead connection. The read still answers, and
/// the one-connection pool serves the next call from a fresh backend — the
/// broken connection was discarded, not handed back out.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_failed_rollback_after_truncation_discards_the_connection() {
    let adapter = single_connection_adapter().await;
    let pid = |result: db_mcp_gateway::exec::ExecResult| result.rows[0][0].clone();
    let before = pid(adapter
        .execute(query("SELECT pg_backend_pid()", Access::ReadOnly, 1))
        .await
        .expect("first backend"));

    let truncated = adapter
        .execute(query(
            "SELECT g FROM generate_series(1, 3) g \
             UNION ALL SELECT pg_terminate_backend(pg_backend_pid())::int",
            Access::ReadOnly,
            1,
        ))
        .await
        .expect("a truncated read is still an answer");
    assert!(truncated.truncated);
    assert_eq!(truncated.rows, vec![vec![json!(1)]]);

    let after = pid(adapter
        .execute(query("SELECT pg_backend_pid()", Access::ReadOnly, 1))
        .await
        .expect("the pool recovers"));
    assert_ne!(
        before, after,
        "the terminated backend's connection was reused"
    );
}

/// Listings kept in flight by [`activity_listings_never_hold_back_a_write_cancel`]:
/// well over the write tier's two cancel connections.
const LISTINGS: usize = 16;

/// How long a cancel may take with every listing in flight.
const PROMPT: Duration = Duration::from_secs(2);

/// A write of `adapter`, `SELECT pg_sleep(20)`, running as `request_id`.
fn spawn_write(
    adapter: &Arc<PgAdapter>,
    request_id: Uuid,
) -> tokio::task::JoinHandle<Result<db_mcp_gateway::exec::ExecResult, ExecError>> {
    let adapter = Arc::clone(adapter);
    tokio::spawn(async move {
        adapter
            .execute(ExecQuery {
                request_id,
                ..query("SELECT pg_sleep(20)", Access::ReadWrite, 1)
            })
            .await
    })
}

/// Whether a backend still runs `request_id`'s statement, polled until
/// [`PROMPT`] runs out. An aborted transaction left `idle in transaction`
/// keeps its tag, so only `active` counts.
async fn still_running_after_prompt(monitor: &sqlx::PgPool, request_id: Uuid) -> bool {
    let deadline = Instant::now() + PROMPT;
    loop {
        let running: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE state = 'active' AND application_name LIKE $1",
        )
        .bind(format!("dbmcp-{}-%", request_id.simple()))
        .fetch_one(monitor)
        .await
        .expect("pg_stat_activity lookup");
        if running == 0 {
            return false;
        }
        if Instant::now() >= deadline {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn activity_listings_never_hold_back_a_write_cancel() {
    let adapter = Arc::new(writable_adapter().await);
    let monitor = sqlx::PgPool::connect(&owner_url())
        .await
        .expect("target owner connection");
    let stop = Arc::new(AtomicBool::new(false));
    let listings: Vec<_> = (0..LISTINGS)
        .map(|_| {
            let (adapter, stop) = (Arc::clone(&adapter), Arc::clone(&stop));
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    adapter.db_activity(activity()).await?;
                }
                Ok::<(), ExecError>(())
            })
        })
        .collect();

    // `cancel_request`, as the `cancel_query` tool sends it.
    let victim_id = Uuid::new_v4();
    let victim = spawn_write(&adapter, victim_id);
    assert!(lists_write(&adapter, victim_id).await, "write never listed");
    let started = Instant::now();
    let cancelled = adapter.cancel_request(victim_id).await;
    assert!(matches!(cancelled, Ok(true)), "{cancelled:?}");
    assert!(
        started.elapsed() < PROMPT,
        "cancel_request took {:?} behind the listings",
        started.elapsed()
    );
    let outcome = victim.await.expect("victim task");
    assert!(matches!(outcome, Err(ExecError::Cancelled)), "{outcome:?}");

    // `CancelOnDrop`, as an agent disconnect fires it.
    let dropped_id = Uuid::new_v4();
    let dropped = spawn_write(&adapter, dropped_id);
    assert!(
        lists_write(&adapter, dropped_id).await,
        "write never listed"
    );
    dropped.abort();
    assert!(
        !still_running_after_prompt(&monitor, dropped_id).await,
        "the dropped write was not cancelled within {PROMPT:?} behind the listings"
    );

    stop.store(true, Ordering::Relaxed);
    for listing in listings {
        listing
            .await
            .expect("listing task")
            .expect("listings answer throughout");
    }
}
