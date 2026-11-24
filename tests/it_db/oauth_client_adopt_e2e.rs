//! `/authorize` adoption of an unknown `client_id` against the real state
//! DB: it never rewrites a live registration, and a registry outage is an
//! outage — not an unknown client to adopt.

use db_mcp_gateway::auth::oauth::{ClientRegistry, StoreError};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

use crate::common::env::state_pool;
use crate::common::gateway::no_redirect_client;
use crate::oauth_client_ttl_e2e::{authorize, cleanup, spawn_gateway};

/// Adoption takes a caller-chosen id. If that id is live — the lookup that
/// preceded it missed the row — adoption hands back the registration as it
/// stands instead of pointing it at the caller's redirect.
#[tokio::test]
#[serial_test::parallel(world)]
async fn adopting_a_live_client_keeps_its_redirect_uris() {
    let pool = state_pool().await;
    let registry = ClientRegistry::with_db(pool.clone());
    let client_id = format!("mcp-test-{}", Uuid::new_v4().simple());
    let registered = vec!["https://app.example/cb".to_string()];
    registry
        .insert(client_id.clone(), registered.clone())
        .await
        .expect("registered");

    let adopted = registry
        .adopt(client_id.clone(), "http://127.0.0.1:9/cb".into())
        .await
        .expect("adoption of a live id is not an error");
    assert_eq!(adopted.redirect_uris, registered);
    assert_eq!(
        registry.redirect_uris(&client_id).await,
        Ok(Some(registered))
    );

    cleanup(&pool, &client_id).await;
}

/// With the state DB unreachable the registry reports an outage rather than
/// "unknown client", and `/authorize` answers 503 for a loopback redirect
/// instead of adopting the id.
#[tokio::test]
#[serial_test::parallel(world)]
async fn authorize_during_a_registry_outage_is_503_and_adopts_nothing() {
    let pool = state_pool().await;
    let client_id = format!("mcp-test-{}", Uuid::new_v4().simple());
    let registered = vec!["https://app.example/cb".to_string()];
    ClientRegistry::with_db(pool.clone())
        .insert(client_id.clone(), registered.clone())
        .await
        .expect("registered");

    let down = state_pool().await;
    down.close().await;
    let registry = ClientRegistry::with_db(down);
    assert_eq!(registry.lookup(&client_id).await, Err(StoreError::Backend));
    let gateway = spawn_gateway(&pool, registry).await;

    let resp = authorize(&no_redirect_client(), &gateway, &client_id).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    assert_eq!(
        ClientRegistry::with_db(pool.clone())
            .redirect_uris(&client_id)
            .await,
        Ok(Some(registered)),
        "the live registration is untouched"
    );

    cleanup(&pool, &client_id).await;
}
