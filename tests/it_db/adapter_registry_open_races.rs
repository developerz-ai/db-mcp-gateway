//! `AdapterRegistry` under two races the single-flight slot used to lose:
//!
//! - a request still holding the pre-reload config snapshot reaches the
//!   registry after the reload evicted the slot. Its open (old role) must not
//!   become the adapter later requests on the new config are served from;
//! - callers queued on one open of a dead target must share that failure,
//!   not each run their own open back to back.
//!
//! Audit assertion intentionally skipped: these drive the exec layer's
//! registry directly, never the tool-dispatch path that writes audit rows.

use std::time::{Duration, Instant};

use crate::adapter_registry_concurrency::spawn_blackhole;
use crate::common::pg_target::{self, READ_ROLE, READ_ROLE_PASSWORD, TARGET_USER};
use db_mcp_gateway::config::{Database, Password, Server};
use db_mcp_gateway::exec::{AdapterRegistry, DbAdapter, ExecError, ExecQuery};
use uuid::Uuid;

/// Restated from `PgAdapter` (not exported); see
/// `adapter_registry_concurrency::POOL_ACQUIRE_TIMEOUT`.
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

async fn current_user(adapter: &dyn DbAdapter) -> String {
    let result = adapter
        .execute(ExecQuery {
            sql: "SELECT current_user::text",
            binds: &[],
            statement_timeout_ms: Some(5_000),
            row_limit: 1,
            access: db_mcp_gateway::exec::Access::ReadOnly,
            dry_run: false,
            request_id: Uuid::new_v4(),
        })
        .await
        .expect("current_user runs");
    result.rows[0][0]
        .as_str()
        .expect("current_user is text")
        .to_owned()
}

/// The same `(server, database)` key, re-pointed at the read role — what a
/// reload that narrows `role:` produces.
fn narrowed(database: &Database) -> Database {
    Database {
        role: READ_ROLE.to_string(),
        password: Password::Literal(READ_ROLE_PASSWORD.into()),
        ..database.clone()
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn adapter_opened_from_a_pre_reload_snapshot_is_not_served_after_it() {
    pg_target::ensure_read_role().await;
    let server: Server = pg_target::server();
    let before = pg_target::database();
    let after = narrowed(&before);
    let registry = AdapterRegistry::new();

    let warm = registry.get_or_open(&server, &before).await.expect("opens");
    assert_eq!(current_user(warm.as_ref()).await, TARGET_USER);

    // The reload swaps the config, then evicts the changed key.
    registry.evict(&server.name, &before.name).await;
    // A request that loaded its snapshot before the swap opens afterwards.
    let straggler = registry.get_or_open(&server, &before).await.expect("opens");
    assert_eq!(current_user(straggler.as_ref()).await, TARGET_USER);

    let next = registry.get_or_open(&server, &after).await.expect("opens");
    assert_eq!(
        current_user(next.as_ref()).await,
        READ_ROLE,
        "a request on the new config ran as the pre-reload role"
    );
    let again = registry.get_or_open(&server, &after).await.expect("cached");
    assert!(
        std::sync::Arc::ptr_eq(&next, &again),
        "the new-config adapter is reused once open"
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn callers_queued_on_a_failing_open_share_its_failure() {
    let mut server = pg_target::server();
    server.port = spawn_blackhole().await;
    let database = pg_target::database();
    let registry = AdapterRegistry::new();

    let started = Instant::now();
    let results = futures::future::join_all((0..4).map(|_| {
        let (registry, server, database) = (registry.clone(), server.clone(), database.clone());
        async move { registry.get_or_open(&server, &database).await }
    }))
    .await;
    let elapsed = started.elapsed();

    assert!(results.iter().all(Result::is_err), "the target is dead");
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(ExecError::Unavailable))),
        "queued callers answer from the remembered failure"
    );
    let two_opens = POOL_ACQUIRE_TIMEOUT + POOL_ACQUIRE_TIMEOUT / 2;
    assert!(
        elapsed < two_opens,
        "queued callers each re-ran the open: {elapsed:?} for 4 callers"
    );
}
