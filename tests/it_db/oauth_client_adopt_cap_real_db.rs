//! `/authorize` adoption at the registry cap, against the real state DB: an
//! adoption that finds its target live writes nothing, so it must evict
//! nothing either — least of all the target, which a never-used
//! registration at the head of the eviction order would otherwise be.
//!
//! `#[serial_test::serial(world)]`: both tests fill the shared
//! `oauth_clients` table to the cap.

use db_mcp_gateway::auth::oauth::ClientRegistry;
use sqlx::PgPool;
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
    for adoption in futures::future::join_all(adoptions).await {
        let (adopts_target, adopted) = adoption.expect("join");
        if adopts_target {
            let adopted = adopted.expect("adoption of a live id");
            assert_eq!(adopted.redirect_uris, vec![SEEDED_URI.to_string()]);
        }
    }
    assert_eq!(
        registry.redirect_uris(&target).await,
        Ok(Some(vec![SEEDED_URI.to_string()])),
    );

    delete_prefixed(&pool, &prefix).await;
}
