//! `/authorize` adoption at the registry cap, against the real state DB: an
//! adoption that finds its target live writes nothing, so it must evict
//! nothing either — least of all the target, which a never-used
//! registration at the head of the eviction order would otherwise be.
//!
//! Capped writes are also serialised on the registry lock, and an eviction
//! re-tests its victim: the races below hold one writer open mid-transaction
//! and start the other behind it.
//!
//! `#[serial_test::serial(world)]`: every test fills the shared
//! `oauth_clients` table to the cap.

use std::future::Future;
use std::time::{Duration, Instant};

use db_mcp_gateway::auth::oauth::ClientRegistry;
use db_mcp_gateway::state::oauth as db;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::common::env::state_pool;

const SEEDED_URI: &str = "https://seed/cb";

/// Fill the table to `CLIENT_CAP` with never-used rows `<prefix>1..`, oldest
/// first.
async fn seed_to_cap(pool: &PgPool, prefix: &str) {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, created_at, expires_at) \
         SELECT $1 || g, jsonb_build_array($2::text), \
                now() - make_interval(secs => 3000 - g * 0.1), \
                now() - make_interval(secs => 3000 - g * 0.1) + interval '1 hour' \
         FROM generate_series(1, 10000 - (SELECT count(*) FROM oauth_clients)) g",
    )
    .bind(prefix)
    .bind(SEEDED_URI)
    .execute(pool)
    .await
    .expect("seed to cap");
}

async fn seeded_rows(pool: &PgPool, prefix: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM oauth_clients WHERE client_id LIKE $1")
        .bind(format!("{prefix}%"))
        .fetch_one(pool)
        .await
        .expect("count seeded rows")
}

/// A registry write of the test's own, held open before its commit.
struct OpenWrite {
    tx: Transaction<'static, Postgres>,
    pid: i32,
}

impl OpenWrite {
    async fn begin(pool: &PgPool) -> Self {
        let mut tx = pool.begin().await.expect("begin");
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("pid");
        Self { tx, pid }
    }

    /// Start `call`, wait until it is blocked behind this transaction,
    /// commit, and return what the call answers.
    async fn commit_once_waited_on<T: Send + 'static>(
        self,
        pool: &PgPool,
        call: impl Future<Output = T> + Send + 'static,
    ) -> T {
        let call = self.start_waiting(pool, call).await;
        self.tx.commit().await.expect("commit the open write");
        call.await.expect("join")
    }

    /// Start `call` and return once it is blocked behind this transaction.
    async fn start_waiting<T: Send + 'static>(
        &self,
        pool: &PgPool,
        call: impl Future<Output = T> + Send + 'static,
    ) -> JoinHandle<T> {
        let call = tokio::spawn(call);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let waited_on: bool = sqlx::query_scalar(
                "SELECT exists(SELECT 1 FROM pg_stat_activity \
                 WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(self.pid)
            .fetch_one(pool)
            .await
            .expect("blocking check");
            if waited_on {
                break;
            }
            assert!(
                !call.is_finished() && Instant::now() < deadline,
                "the call did not wait for the open registry write"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        call
    }
}

async fn total_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
        .fetch_one(pool)
        .await
        .expect("count rows")
}

async fn delete_prefixed(pool: &PgPool, prefix: &str) {
    sqlx::query("DELETE FROM oauth_clients WHERE client_id LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await
        .expect("cleanup seeded rows");
}

/// Concurrent adoptions of one live id — the oldest evictable row at the cap
/// — each with its own redirect: every one gets the registration as it
/// stands, and no row is evicted.
#[tokio::test]
#[serial_test::serial(world)]
async fn concurrent_adoptions_of_a_live_client_at_the_cap_evict_nothing() {
    let pool = state_pool().await;
    let prefix = format!("adoptcap-{}-", Uuid::new_v4().simple());
    seed_to_cap(&pool, &prefix).await;
    let seeded = seeded_rows(&pool, &prefix).await;
    let registry = ClientRegistry::with_db(pool.clone());
    let target = format!("{prefix}1");

    let adoptions = (0..16).map(|port| {
        let (registry, target) = (registry.clone(), target.clone());
        tokio::spawn(async move {
            registry
                .adopt(target, format!("http://127.0.0.1:{port}/cb"))
                .await
        })
    });
    for adoption in futures::future::join_all(adoptions).await {
        let adopted = adoption.expect("join").expect("adoption of a live id");
        assert_eq!(adopted.redirect_uris, vec![SEEDED_URI.to_string()]);
    }

    assert_eq!(
        registry.redirect_uris(&target).await,
        Ok(Some(vec![SEEDED_URI.to_string()])),
        "the live registration's redirect URIs were rewritten"
    );
    assert_eq!(
        seeded_rows(&pool, &prefix).await,
        seeded,
        "an adoption that wrote nothing evicted a row"
    );

    delete_prefixed(&pool, &prefix).await;
}

/// Newcomers make room at the cap while others adopt a live, used client:
/// every adoption of it gets the registration as it stands.
#[tokio::test]
#[serial_test::serial(world)]
async fn adoptions_racing_newcomers_at_the_cap_never_rewrite_a_live_client() {
    let pool = state_pool().await;
    let prefix = format!("adoptrace-{}-", Uuid::new_v4().simple());
    seed_to_cap(&pool, &prefix).await;
    let registry = ClientRegistry::with_db(pool.clone());
    let target = format!("{prefix}1");
    assert_eq!(registry.promote(&target).await, Ok(true));

    let adoptions = (0..16).map(|n| {
        let registry = registry.clone();
        let adopts_target = n % 2 == 0;
        let client_id = if adopts_target {
            target.clone()
        } else {
            format!("{prefix}new-{n}")
        };
        tokio::spawn(async move {
            let adopted = registry
                .adopt(client_id, format!("http://127.0.0.1:{n}/cb"))
                .await;
            (adopts_target, adopted)
        })
    });
    for (n, adoption) in futures::future::join_all(adoptions)
        .await
        .into_iter()
        .enumerate()
    {
        let (adopts_target, adopted) = adoption.expect("join");
        let adopted = adopted.expect("an adoption at a cap with evictable rows");
        let expected = if adopts_target {
            SEEDED_URI.to_string()
        } else {
            format!("http://127.0.0.1:{n}/cb")
        };
        assert_eq!(adopted.redirect_uris, vec![expected], "adoption {n}");
    }
    assert_eq!(
        registry.redirect_uris(&target).await,
        Ok(Some(vec![SEEDED_URI.to_string()])),
    );
    for n in (1..16).step_by(2) {
        let newcomer = registry.redirect_uris(&format!("{prefix}new-{n}")).await;
        assert!(matches!(newcomer, Ok(Some(_))), "newcomer {n} was evicted");
    }
    assert_eq!(
        total_rows(&pool).await,
        10_000,
        "each newcomer evicts exactly one row: no more, and never none"
    );

    delete_prefixed(&pool, &prefix).await;
}

/// An adoption of a new id is still uncommitted when a second adoption of
/// that id starts at the cap. The second must wait for the first and then
/// find the id live — not evict a bystander to make room for a row it never
/// writes.
#[tokio::test]
#[serial_test::serial(world)]
async fn adopting_an_id_another_adoption_is_committing_evicts_no_bystander() {
    let pool = state_pool().await;
    let prefix = format!("adoptsame-{}-", Uuid::new_v4().simple());
    seed_to_cap(&pool, &prefix).await;
    let seeded = seeded_rows(&pool, &prefix).await;
    let registry = ClientRegistry::with_db(pool.clone());
    let contested = format!("{prefix}contested");

    let mut first = OpenWrite::begin(&pool).await;
    db::lock_client_registry(&mut *first.tx)
        .await
        .expect("registry lock");
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, expires_at) \
         VALUES ($1, jsonb_build_array('http://127.0.0.1:1/cb'), now() + interval '1 hour')",
    )
    .bind(&contested)
    .execute(&mut *first.tx)
    .await
    .expect("first adoption's row");
    let second = {
        let (registry, contested) = (registry.clone(), contested.clone());
        async move {
            registry
                .adopt(contested, "http://127.0.0.1:2/cb".into())
                .await
        }
    };
    let adopted = first.commit_once_waited_on(&pool, second).await;

    assert_eq!(
        adopted.expect("adoption of a live id").redirect_uris,
        vec!["http://127.0.0.1:1/cb".to_string()],
        "the second adoption must get the first one's registration"
    );
    assert_eq!(
        seeded_rows(&pool, &prefix).await,
        seeded + 1,
        "an adoption that wrote nothing evicted a bystander"
    );

    delete_prefixed(&pool, &prefix).await;
}

/// `/token` promotes the row a capped insert has picked as its victim, and
/// commits while the insert waits on that row. The eviction re-tests the
/// row it is about to delete, so the now-used registration survives. The
/// promotion here skips the registry lock on purpose: the re-test alone
/// must hold.
#[tokio::test]
#[serial_test::serial(world)]
async fn a_victim_promoted_under_the_eviction_is_not_deleted() {
    let pool = state_pool().await;
    let prefix = format!("promoterace-{}-", Uuid::new_v4().simple());
    // Litter of earlier runs that an eviction would pick before the victim.
    sqlx::query(
        "DELETE FROM oauth_clients WHERE expires_at <= now() \
           OR (created_at <= now() - interval '59 minutes' \
               AND expires_at <= created_at + interval '1 hour')",
    )
    .execute(&pool)
    .await
    .expect("clear older evictable rows");
    seed_to_cap(&pool, &prefix).await;
    // Never used, a minute from lapsing: the oldest row an eviction may take.
    let victim = format!("{prefix}victim");
    sqlx::query(
        "UPDATE oauth_clients SET client_id = $1, \
           created_at = now() - interval '59 minutes', \
           expires_at = now() + interval '1 minute' \
         WHERE client_id = $2",
    )
    .bind(&victim)
    .bind(format!("{prefix}1"))
    .execute(&pool)
    .await
    .expect("make the victim the oldest row");
    let registry = ClientRegistry::with_db(pool.clone());

    let mut promotion = OpenWrite::begin(&pool).await;
    sqlx::query(
        "UPDATE oauth_clients SET expires_at = now() + interval '90 days' WHERE client_id = $1",
    )
    .bind(&victim)
    .execute(&mut *promotion.tx)
    .await
    .expect("promote the victim");
    let newcomer = {
        let (registry, id) = (registry.clone(), format!("{prefix}newcomer"));
        async move { registry.adopt(id, "http://127.0.0.1:3/cb".into()).await }
    };
    // Refused or admitted, the newcomer is not the subject here.
    let _ = promotion.commit_once_waited_on(&pool, newcomer).await;

    assert_eq!(
        registry.redirect_uris(&victim).await,
        Ok(Some(vec![SEEDED_URI.to_string()])),
        "a registration promoted before the eviction reached it was deleted"
    );

    delete_prefixed(&pool, &prefix).await;
}

/// The production promotion takes the registry lock, so it never commits
/// between a capped insert's snapshot and its eviction.
#[tokio::test]
#[serial_test::serial(world)]
async fn promotion_waits_for_the_registry_lock() {
    let pool = state_pool().await;
    let registry = ClientRegistry::with_db(pool.clone());
    let client_id = format!("promotelock-{}", Uuid::new_v4().simple());
    registry
        .insert(client_id.clone(), vec![SEEDED_URI.to_string()])
        .await
        .expect("register");

    let mut held = OpenWrite::begin(&pool).await;
    db::lock_client_registry(&mut *held.tx)
        .await
        .expect("registry lock");
    let promote = {
        let (registry, client_id) = (registry.clone(), client_id.clone());
        async move { registry.promote(&client_id).await }
    };
    let promoted = held.commit_once_waited_on(&pool, promote).await;

    assert_eq!(promoted, Ok(true));
    delete_prefixed(&pool, &client_id).await;
}

/// A promotion that waited on the registry lock while its client lapsed
/// judges expiry when it gets the lock, not when its transaction began: the
/// lapsed row is not renewed.
#[tokio::test]
#[serial_test::serial(world)]
async fn a_client_that_lapsed_while_promotion_waited_is_not_renewed() {
    let pool = state_pool().await;
    let registry = ClientRegistry::with_db(pool.clone());
    let client_id = format!("promotelapse-{}", Uuid::new_v4().simple());
    registry
        .insert(client_id.clone(), vec![SEEDED_URI.to_string()])
        .await
        .expect("register");

    let mut held = OpenWrite::begin(&pool).await;
    db::lock_client_registry(&mut *held.tx)
        .await
        .expect("registry lock");
    let promote = {
        let (registry, client_id) = (registry.clone(), client_id.clone());
        async move { registry.promote(&client_id).await }
    };
    // The promotion's transaction began while the client was live.
    let promote = held.start_waiting(&pool, promote).await;
    sqlx::query("UPDATE oauth_clients SET expires_at = clock_timestamp() WHERE client_id = $1")
        .bind(&client_id)
        .execute(&mut *held.tx)
        .await
        .expect("lapse the client");
    held.tx.commit().await.expect("release the registry lock");

    assert_eq!(
        promote.await.expect("join"),
        Ok(false),
        "a client that lapsed while promotion waited was renewed"
    );
    delete_prefixed(&pool, &client_id).await;
}
