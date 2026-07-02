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

use db_mcp_gateway::transport::ClientRegistry;
use sqlx::PgPool;

/// These tests share one `oauth_clients` table, and the cap test fills it to
/// `CLIENT_CAP` — a concurrent insert from any sibling test would be refused
/// at the cap and flake. Serialize the whole file.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn pool() -> PgPool {
    db_mcp_gateway::state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

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
async fn registration_survives_a_restart() {
    let _serial = SERIAL.lock().await;
    let pool = pool().await;
    let client_id = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &client_id).await;

    let before_restart = ClientRegistry::with_db(pool.clone());
    assert!(
        before_restart
            .insert(client_id.clone(), vec!["http://127.0.0.1:0/cb".into()])
            .await
    );

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
async fn re_register_updates_redirect_uris() {
    let _serial = SERIAL.lock().await;
    let pool = pool().await;
    let client_id = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &client_id).await;

    let reg = ClientRegistry::with_db(pool.clone());
    assert!(
        reg.insert(client_id.clone(), vec!["https://a/cb".into()])
            .await
    );
    assert!(
        reg.insert(client_id.clone(), vec!["https://b/cb".into()])
            .await
    );
    assert_eq!(
        reg.redirect_uris(&client_id).await,
        Some(vec!["https://b/cb".into()])
    );

    cleanup(&pool, &client_id).await;
}

/// An expired registration is not returned by lookup and is swept by the
/// insert-time GC (`DELETE ... WHERE expires_at <= now()`) — the DB-backed
/// analogue of the in-memory store's TTL. We age the row directly rather than
/// sleep out the 24h TTL.
#[tokio::test]
async fn expired_registration_is_swept_and_not_returned() {
    let _serial = SERIAL.lock().await;
    let pool = pool().await;
    let stale = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &stale).await;

    let reg = ClientRegistry::with_db(pool.clone());
    assert!(reg.insert(stale.clone(), vec!["https://a/cb".into()]).await);

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

    // ...and the next insert's GC pass physically removes it.
    let fresh = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    assert!(reg.insert(fresh.clone(), vec!["https://b/cb".into()]).await);
    let still_there: bool =
        sqlx::query_scalar("SELECT exists(SELECT 1 FROM oauth_clients WHERE client_id = $1)")
            .bind(&stale)
            .fetch_one(&pool)
            .await
            .expect("existence check");
    assert!(!still_there, "GC must have deleted the expired row");

    cleanup(&pool, &fresh).await;
    cleanup(&pool, &stale).await;
}

/// The 10k hard cap, against the real SQL backend: at capacity a brand-new
/// `client_id` is refused, but an already-registered one may still update (an
/// upsert doesn't grow the table). Seeds the cap in one statement rather than
/// 10k round-trips; the seeded rows carry a live TTL so the insert-time GC keeps
/// them. Everything is namespaced under a unique prefix and cleaned up.
#[tokio::test]
async fn at_cap_rejects_new_but_updates_existing_real_db() {
    let _serial = SERIAL.lock().await;
    let pool = pool().await;
    let prefix = format!("capfill-{}-", uuid::Uuid::new_v4().simple());

    // Fill to the 10k cap in a single INSERT. Even if the table holds other
    // rows, this guarantees count(*) >= CLIENT_CAP for the duration.
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, expires_at) \
         SELECT $1 || g, '[\"https://seed/cb\"]'::jsonb, now() + interval '1 hour' \
         FROM generate_series(1, 10000) g",
    )
    .bind(&prefix)
    .execute(&pool)
    .await
    .expect("seed to cap");

    let reg = ClientRegistry::with_db(pool.clone());

    // At cap: a brand-new client is refused (fails closed as `false`).
    let newcomer = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    assert!(
        !reg.insert(newcomer.clone(), vec!["https://new/cb".into()])
            .await,
        "a new client must be rejected at the cap"
    );
    assert_eq!(reg.redirect_uris(&newcomer).await, None);

    // But an already-registered client updating its URIs still succeeds — the
    // upsert doesn't grow the table, so it bypasses the cap check.
    let existing = format!("{prefix}1");
    assert!(
        reg.insert(existing.clone(), vec!["https://updated/cb".into()])
            .await,
        "an existing client must still update at the cap"
    );
    assert_eq!(
        reg.redirect_uris(&existing).await,
        Some(vec!["https://updated/cb".into()])
    );

    sqlx::query("DELETE FROM oauth_clients WHERE client_id LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await
        .expect("cleanup seeded rows");
}
