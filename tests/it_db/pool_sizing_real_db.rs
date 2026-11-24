//! `pool:` sizing reaches the live pools: `min_connections` connections are
//! opened and kept, idle ones close after `idle_timeout_s` (Postgres via
//! sqlx's reaper, Redis via the adapter's own `sweep_idle`). Each check polls
//! the server's own view of its clients to a deadline — no fixed sleeps.
//!
//! Audit assertion intentionally skipped: these drive the adapters directly,
//! never the tool-dispatch path that writes audit rows.

use std::time::Duration;

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password};
use db_mcp_gateway::exec::{PgAdapter, PoolSizing};
use redis::aio::MultiplexedConnection;
use sqlx::PgPool;

use crate::common::pg_target::{database, owner_url, server};
use crate::common::redis_target::{self, Flavor, admin, admin_cmd, unique_key};

/// Login roles no other test connects as, one per test, so each test's
/// backends are its own.
const MIN_ROLE: &str = "dbmcp_test_pool_min";
const IDLE_ROLE: &str = "dbmcp_test_pool_idle";
const POOL_PASSWORD: &str = "pool-dev-only";
const DEADLINE: Duration = Duration::from_secs(10);

async fn owner() -> PgPool {
    PgPool::connect(&owner_url())
        .await
        .expect("target-db reachable")
}

async fn ensure_role(owner: &PgPool, role: &str) {
    let sql = format!(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') \
         THEN CREATE ROLE {role} LOGIN PASSWORD '{POOL_PASSWORD}'; END IF; END $$"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(owner)
        .await
        .expect("provision the pool role");
}

async fn backends(owner: &PgPool, role: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename = $1")
        .bind(role)
        .fetch_one(owner)
        .await
        .expect("pg_stat_activity")
}

/// Poll `probe` until it satisfies `done`, or fail naming `what`.
async fn eventually(what: &str, mut probe: impl AsyncFnMut() -> i64, done: impl Fn(i64) -> bool) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let mut last = probe().await;
    while !done(last) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: still {last} after {DEADLINE:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        last = probe().await;
    }
}

async fn open(role: &str, sizing: PoolSizing) -> PgAdapter {
    let owner = owner().await;
    ensure_role(&owner, role).await;
    let database = Database {
        role: role.to_string(),
        password: Password::Literal(POOL_PASSWORD.into()),
        ..database()
    };
    PgAdapter::open(&server(), &database, sizing, DetachedTasks::new())
        .await
        .expect("open as the pool role")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn pg_min_connections_are_opened() {
    let owner = owner().await;
    let sizing = PoolSizing {
        max_connections: 4,
        min_connections: 3,
        idle_timeout: Duration::from_secs(300),
    };
    let adapter = open(MIN_ROLE, sizing).await;
    eventually(
        MIN_ROLE,
        async || backends(&owner, MIN_ROLE).await,
        |n| n >= 3,
    )
    .await;
    drop(adapter);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn pg_idle_connections_close_after_the_idle_timeout() {
    let owner = owner().await;
    let sizing = PoolSizing {
        max_connections: 2,
        min_connections: 0,
        idle_timeout: Duration::from_millis(300),
    };
    let adapter = open(IDLE_ROLE, sizing).await;
    eventually(
        IDLE_ROLE,
        async || backends(&owner, IDLE_ROLE).await,
        |n| n == 0,
    )
    .await;
    drop(adapter);
}

/// Every client the server lists but `side` itself.
async fn other_clients(side: &mut MultiplexedConnection) -> i64 {
    let own = match admin_cmd(side, &["CLIENT", "ID"]).await {
        redis::Value::Int(id) => id.to_string(),
        other => panic!("CLIENT ID: {other:?}"),
    };
    let list = match admin_cmd(side, &["CLIENT", "LIST"]).await {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes).expect("UTF-8 CLIENT LIST"),
        redis::Value::VerbatimString { text, .. } => text,
        other => panic!("CLIENT LIST: {other:?}"),
    };
    let others = list
        .lines()
        .filter_map(|line| line.split(' ').find_map(|field| field.strip_prefix("id=")))
        .filter(|id| *id != own)
        .count();
    i64::try_from(others).expect("client count fits i64")
}

/// The pooled connection a read left idle is closed by the sweeper once it
/// is older than `idle_timeout`, while the adapter itself stays alive.
#[tokio::test]
#[serial_test::serial(world)]
async fn redis_sweep_closes_connections_idle_past_the_timeout() {
    for flavor in Flavor::ALL {
        let mut side = admin(flavor).await;
        let before = other_clients(&mut side).await;
        let sizing = PoolSizing {
            max_connections: 1,
            min_connections: 0,
            idle_timeout: Duration::from_millis(300),
        };
        let adapter = redis_target::adapter(flavor, sizing).await;
        let get = format!(r#"["GET","{}"]"#, unique_key("sweep"));
        redis_target::ok(&adapter, flavor, &get, 10).await;
        let name = flavor.name();
        // The read left its connection idle in the pool (the sweep's first
        // tick is a whole timeout away).
        let idle = other_clients(&mut side).await;
        assert!(
            idle > before,
            "{name}: no pooled connection ({idle} <= {before})"
        );
        eventually(
            name,
            async || other_clients(&mut side).await,
            |n| n <= before,
        )
        .await;
        drop(adapter);
    }
}
