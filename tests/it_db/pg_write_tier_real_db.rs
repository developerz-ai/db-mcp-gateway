//! The write tier across replicas and under broken credentials, and the
//! connection a failed truncation rollback leaves behind.
//!
//! - Another replica's write is listed by `db_activity` and stopped by
//!   `cancel_request` on a replica that never wrote (two adapters on one
//!   target stand in for two gateway processes).
//! - A write credential that does not resolve, or that the target refuses,
//!   fails writes only: reads keep working and the adapter is not stale.
//! - A truncated read whose rollback fails leaves no reused connection.
//!
//! Target: `target-db` (`bin/dev up`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::Password;
use db_mcp_gateway::exec::{
    Access, ActivityQuery, DbAdapter, ExecError, ExecQuery, PgAdapter, PoolSizing,
};
use serde_json::json;
use uuid::Uuid;

use crate::common::pg_target::{
    ensure_read_role, server, single_connection_adapter, writable_adapter, writable_database,
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
