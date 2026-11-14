//! Real-DB tests for the DB-backed Dynamic-Client-Registration store.
//!
//! The whole point of migration 0008 is that a registration survives a process
//! restart — the fix for the `invalid_client` wedge where a redeploy dropped the
//! in-memory registry and a client that cached its `client_id` got a hard error.
//! A fresh `ClientRegistry` over the *same* pool models "same state DB, new pod":
//! it must still resolve a client registered before the "restart".
//!
//! No mocking — these run against the real dev state DB (`bin/dev up`), same as
//! the session-cache real-DB tests.
//!
//! All tests are `#[serial_test::serial(world)]`: they share one global
//! `oauth_clients` table, and the cap tests seed it to the 10k `CLIENT_CAP`.
//! Run beside any other test, that seed would evict or refuse its
//! registration (the OAuth suites `/register` too) — a nondeterministic flake
//! where the victim changes per run.

use crate::common::env::state_pool;
use db_mcp_gateway::auth::oauth::{ClientRegistry, StoreError};
use sqlx::PgPool;

async fn cleanup(pool: &PgPool, client_id: &str) {
    sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(pool)
        .await
        .expect("cleanup");
}

/// A client registered against one registry instance is still resolvable from a
/// *new* instance over the same pool — i.e. it survives a pod restart.
#[tokio::test]
#[serial_test::serial(world)]
async fn registration_survives_a_restart() {
    let pool = state_pool().await;
    let client_id = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &client_id).await;

    let before_restart = ClientRegistry::with_db(pool.clone());
    before_restart
        .insert(client_id.clone(), vec!["http://127.0.0.1:0/cb".into()])
        .await
        .expect("registered");

    // New instance, same DB — the "restarted pod".
    let after_restart = ClientRegistry::with_db(pool.clone());
    assert_eq!(
        after_restart.redirect_uris(&client_id).await,
        Some(vec!["http://127.0.0.1:0/cb".into()]),
        "a registration persisted across the restart must still resolve"
    );
    assert_eq!(
        after_restart.redirect_uris("mcp-never-registered").await,
        None,
        "an unknown client_id still resolves to None"
    );

    cleanup(&pool, &client_id).await;
}

/// Re-registering an existing `client_id` overwrites its redirect URIs (upsert),
/// rather than erroring or duplicating the row.
#[tokio::test]
#[serial_test::serial(world)]
async fn re_register_updates_redirect_uris() {
    let pool = state_pool().await;
    let client_id = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &client_id).await;

    let reg = ClientRegistry::with_db(pool.clone());
    reg.insert(client_id.clone(), vec!["https://a/cb".into()])
        .await
        .expect("registered");
    reg.insert(client_id.clone(), vec!["https://b/cb".into()])
        .await
        .expect("registered");
    assert_eq!(
        reg.redirect_uris(&client_id).await,
        Some(vec!["https://b/cb".into()])
    );

    cleanup(&pool, &client_id).await;
}

/// An expired registration is not returned by lookup and is swept by the
/// background GC (`DELETE ... WHERE expires_at <= now()`). We age the row
/// directly rather than sleep out the TTL.
#[tokio::test]
#[serial_test::serial(world)]
async fn expired_registration_is_swept_and_not_returned() {
    let pool = state_pool().await;
    let stale = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &stale).await;

    let reg = ClientRegistry::with_db(pool.clone());
    reg.insert(stale.clone(), vec!["https://a/cb".into()])
        .await
        .expect("registered");

    // Backdate the whole row into the past — both columns, so the
    // `expires_at > created_at` CHECK still holds while `expires_at <= now()`.
    sqlx::query(
        "UPDATE oauth_clients \
         SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' \
         WHERE client_id = $1",
    )
    .bind(&stale)
    .execute(&pool)
    .await
    .expect("age the row");

    // Lookup filters on `expires_at > now()`, so the stale row is invisible...
    assert_eq!(
        reg.redirect_uris(&stale).await,
        None,
        "an expired registration must not resolve"
    );

    // ...and the background GC pass physically removes it (the request path
    // never sweeps).
    assert!(reg.gc_expired().await >= 1, "GC must report the stale row");
    let still_there: bool =
        sqlx::query_scalar("SELECT exists(SELECT 1 FROM oauth_clients WHERE client_id = $1)")
            .bind(&stale)
            .fetch_one(&pool)
            .await
            .expect("existence check");
    assert!(!still_there, "GC must have deleted the expired row");

    cleanup(&pool, &stale).await;
}

/// Seed `CLIENT_CAP` rows under `prefix`, `created_at` ascending with `g`, each
/// living `lifetime` past its creation. One statement, not 10k round trips.
async fn seed_to_cap(pool: &PgPool, prefix: &str, lifetime: &str) {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, created_at, expires_at) \
         SELECT $1 || g, '[\"https://seed/cb\"]'::jsonb, \
                now() - make_interval(secs => 20000 - g), \
                now() - make_interval(secs => 20000 - g) + $2::interval \
         FROM generate_series(1, 10000) g",
    )
    .bind(prefix)
    .bind(lifetime)
    .execute(pool)
    .await
    .expect("seed to cap");
}

async fn delete_prefixed(pool: &PgPool, prefix: &str) {
    sqlx::query("DELETE FROM oauth_clients WHERE client_id LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await
        .expect("cleanup seeded rows");
}

/// At the 10k cap, a registration evicts the oldest never-authorised row
/// instead of failing: an unauthenticated `/register` flood only produces
/// such rows, so it recycles its own junk rather than wedging registration.
#[tokio::test]
#[serial_test::serial(world)]
async fn at_cap_evicts_the_oldest_never_authorised_client_real_db() {
    let pool = state_pool().await;
    let prefix = format!("capjunk-{}-", uuid::Uuid::new_v4().simple());
    // Still within the 1 h never-authorised window, so not expired — only
    // evictable.
    seed_to_cap(&pool, &prefix, "1 hour").await;

    let reg = ClientRegistry::with_db(pool.clone());
    let newcomer = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    reg.insert(newcomer.clone(), vec!["https://new/cb".into()])
        .await
        .expect("a registration at the cap evicts junk instead of failing");
    assert_eq!(
        reg.redirect_uris(&newcomer).await,
        Some(vec!["https://new/cb".into()])
    );

    cleanup(&pool, &newcomer).await;
    delete_prefixed(&pool, &prefix).await;
}

/// A store full of clients that have authorized is never evicted from: the
/// newcomer gets `StoreFull`, which `/register` surfaces as `503
/// temporarily_unavailable`.
#[tokio::test]
#[serial_test::serial(world)]
async fn at_cap_of_authorised_clients_is_store_full_real_db() {
    let pool = state_pool().await;
    let prefix = format!("capauth-{}-", uuid::Uuid::new_v4().simple());
    // An expiry past created_at + 1 h marks a client that has authorized.
    seed_to_cap(&pool, &prefix, "90 days").await;

    let reg = ClientRegistry::with_db(pool.clone());
    let newcomer = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    assert_eq!(
        reg.insert(newcomer.clone(), vec!["https://new/cb".into()])
            .await,
        Err(StoreError::StoreFull)
    );
    assert_eq!(reg.redirect_uris(&newcomer).await, None);

    delete_prefixed(&pool, &prefix).await;
}
