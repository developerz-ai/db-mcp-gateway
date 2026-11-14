//! Sessions and refresh chains minted for a `service:` subject before the IdP
//! login reserved the prefix must stop working: a live run showed an SSO user
//! with `sub = service:bot` reading that service account's query history.

mod common;

use std::time::Duration;

use common::env::state_pool;
use db_mcp_gateway::auth::oauth::{GrantIdentity, RefreshTokens};
use db_mcp_gateway::auth::{AuthError, SessionCacheConfig, SessionStore};
use sqlx::PgPool;

const HOUR: Duration = Duration::from_secs(3600);

fn unique_service_sub() -> String {
    format!("service:legacy-{}", uuid::Uuid::new_v4().simple())
}

async fn cleanup(pool: &PgPool, sub: &str) {
    for table in ["oauth_refresh_tokens", "sessions"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_sub = $1"))
            .bind(sub)
            .execute(pool)
            .await
            .expect("cleanup");
    }
}

/// Zero cache TTL: the lookup reads the row, as a fresh replica would.
fn session_store(pool: &PgPool) -> SessionStore {
    SessionStore::with_cache_config(
        pool.clone(),
        SessionCacheConfig {
            ttl: Duration::ZERO,
            max_entries: 100,
        },
    )
}

#[tokio::test]
async fn legacy_session_with_a_service_subject_does_not_authenticate() {
    let pool = state_pool().await;
    let sub = unique_service_sub();
    let session = session_store(&pool)
        .create(&sub, "mallory@example.com", &[], HOUR, None)
        .await
        .expect("seed legacy session row");

    let result = session_store(&pool).lookup(session.id).await;
    assert!(
        matches!(result, Err(AuthError::InvalidSession)),
        "got {result:?}"
    );

    cleanup(&pool, &sub).await;
}

#[tokio::test]
async fn legacy_refresh_chain_with_a_service_subject_does_not_rotate() {
    let pool = state_pool().await;
    let sub = unique_service_sub();
    let refresh = RefreshTokens::with_db(pool.clone(), 24 * HOUR);
    let token = format!("tok-{}", uuid::Uuid::new_v4().simple());
    refresh
        .insert(
            &token,
            GrantIdentity {
                sub: sub.clone(),
                email: "mallory@example.com".into(),
                groups: vec![],
            },
        )
        .await
        .expect("seed legacy chain");

    let rotated = refresh
        .rotate(&session_store(&pool), &token, "next".into(), HOUR)
        .await
        .expect("not a server error");
    assert!(rotated.is_none(), "legacy chain is invalid_grant");

    cleanup(&pool, &sub).await;
}
