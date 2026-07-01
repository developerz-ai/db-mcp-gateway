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
