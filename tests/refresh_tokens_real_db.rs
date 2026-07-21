//! Real-DB tests for the DB-backed refresh-token store (migration 0009).
//!
//! The point of persisting the chain is that a signed-in agent survives a
//! redeploy. In memory, every rollout dropped every chain and forced a full
//! browser SSO login, which quietly capped the real "stay signed in" window at
//! time-until-next-rollout no matter what `REFRESH_TTL_DAYS` said. A fresh
//! `RefreshTokens` over the *same* pool models "same state DB, new pod".
//!
//! No mocking — these run against the real dev state DB (`bin/dev up`), same as
//! the client-registry real-DB tests.

use std::time::Duration;

use db_mcp_gateway::transport::{GrantIdentity, RefreshTokens};
use sqlx::PgPool;

const TTL: Duration = Duration::from_secs(60 * 24 * 3600);

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

/// Namespaced per test so the whole file can run in parallel: every test owns a
/// unique `sub` and cleans up by it.
fn identity(sub: &str) -> GrantIdentity {
    GrantIdentity {
        sub: sub.to_string(),
        email: format!("{sub}@example.com"),
        groups: vec!["engineers".into()],
    }
}

fn unique_sub(tag: &str) -> String {
    format!("rt-{tag}-{}", uuid::Uuid::new_v4().simple())
}

async fn cleanup(pool: &PgPool, sub: &str) {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(sub)
        .execute(pool)
        .await
        .expect("cleanup");
}

/// The regression this table exists for: a chain minted before a restart still
/// renews after it, carrying the identity (groups included) it was minted with.
#[tokio::test]
async fn chain_survives_a_restart() {
    let pool = pool().await;
    let sub = unique_sub("restart");
    let token = format!("tok-{}", uuid::Uuid::new_v4().simple());

    let before_restart = RefreshTokens::with_db(pool.clone(), TTL);
    before_restart
        .insert(&token, identity(&sub))
        .await
        .expect("insert");

    // New instance, same DB — the "restarted pod".
    let after_restart = RefreshTokens::with_db(pool.clone(), TTL);
    let entry = after_restart
        .take(&token)
        .await
        .expect("a persisted chain must still renew after a restart");
    assert_eq!(entry.identity.sub, sub);
    assert_eq!(entry.identity.email, format!("{sub}@example.com"));
    assert_eq!(entry.identity.groups, vec!["engineers".to_string()]);

    cleanup(&pool, &sub).await;
}

/// Rotation is single-use: redeeming a token deletes the row, so a replay of the
/// same value finds nothing (OAuth 2.1 §4.3.1 for public clients).
#[tokio::test]
async fn redemption_consumes_the_token() {
    let pool = pool().await;
    let sub = unique_sub("replay");
    let token = format!("tok-{}", uuid::Uuid::new_v4().simple());

    let store = RefreshTokens::with_db(pool.clone(), TTL);
    store.insert(&token, identity(&sub)).await.expect("insert");
    assert!(store.take(&token).await.is_some(), "first redemption wins");
    assert!(
        store.take(&token).await.is_none(),
        "a replayed refresh token must not renew"
    );

    cleanup(&pool, &sub).await;
}

/// Rotation carries the chain's birth forward verbatim: the absolute TTL is
/// measured from the first mint, so a continuously-rotated chain still dies on
/// schedule (the group-staleness bound, O3b).
#[tokio::test]
async fn rotation_does_not_slide_the_deadline() {
    let pool = pool().await;
    let sub = unique_sub("rotate");
    let first = format!("tok-{}", uuid::Uuid::new_v4().simple());
    let second = format!("tok-{}", uuid::Uuid::new_v4().simple());

    let store = RefreshTokens::with_db(pool.clone(), TTL);
    store.insert(&first, identity(&sub)).await.expect("insert");
    let birth = store.take(&first).await.expect("live").issued_at;
    store
        .insert_rotated(&second, identity(&sub), birth)
        .await
        .expect("rotate");

    let rotated = store.take(&second).await.expect("rotated chain is live");
    assert_eq!(
        rotated.issued_at, birth,
        "rotation must carry the chain birth, not restamp it"
    );

    cleanup(&pool, &sub).await;
}

/// A chain past its absolute TTL does not renew, and GC reaps the row.
#[tokio::test]
async fn expired_chain_is_rejected_and_swept() {
    let pool = pool().await;
    let sub = unique_sub("expired");
    let token = format!("tok-{}", uuid::Uuid::new_v4().simple());

    let store = RefreshTokens::with_db(pool.clone(), TTL);
    // Born a full TTL + a day ago → the materialized `expires_at` is in the past.
    let stale_birth = chrono::Utc::now() - chrono::Duration::days(61);
    store
        .insert_rotated(&token, identity(&sub), stale_birth)
        .await
        .expect("insert");

    assert!(
        store.take(&token).await.is_none(),
        "a chain past its absolute TTL must not renew"
    );

    store.gc_expired().await;
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_refresh_tokens WHERE user_sub = $1")
            .bind(&sub)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(remaining, 0, "GC must delete the lapsed row");

    cleanup(&pool, &sub).await;
}

/// Logout purges every chain for one identity and leaves other users' alone —
/// otherwise a signed-out user could silently mint a fresh session (O4).
#[tokio::test]
async fn purge_for_sub_drops_only_that_identitys_chains() {
    let pool = pool().await;
    let mine = unique_sub("purge-mine");
    let theirs = unique_sub("purge-theirs");
    let a = format!("tok-{}", uuid::Uuid::new_v4().simple());
    let b = format!("tok-{}", uuid::Uuid::new_v4().simple());
    let other = format!("tok-{}", uuid::Uuid::new_v4().simple());

    let store = RefreshTokens::with_db(pool.clone(), TTL);
    store.insert(&a, identity(&mine)).await.expect("insert");
    store.insert(&b, identity(&mine)).await.expect("insert");
    store
        .insert(&other, identity(&theirs))
        .await
        .expect("insert");

    assert_eq!(store.purge_for_sub(&mine).await, 2, "both chains purged");
    assert!(store.take(&a).await.is_none());
    assert!(store.take(&b).await.is_none());
    assert!(
        store.take(&other).await.is_some(),
        "another identity's chain must be untouched"
    );

    cleanup(&pool, &mine).await;
    cleanup(&pool, &theirs).await;
}

/// Lowering `REFRESH_TTL_DAYS` takes effect on chains minted under the old,
/// longer window — the store re-checks the row against the *current* TTL rather
/// than honoring the deadline materialized at mint time.
#[tokio::test]
async fn shortening_the_configured_ttl_applies_to_existing_chains() {
    let pool = pool().await;
    let sub = unique_sub("shrink");
    let token = format!("tok-{}", uuid::Uuid::new_v4().simple());

    let generous = RefreshTokens::with_db(pool.clone(), TTL);
    let birth = chrono::Utc::now() - chrono::Duration::days(30);
    generous
        .insert_rotated(&token, identity(&sub), birth)
        .await
        .expect("insert");

    // Same row, restarted with a 7-day window: 30 days old is now past the cap.
    let strict = RefreshTokens::with_db(pool.clone(), Duration::from_secs(7 * 24 * 3600));
    assert!(
        strict.take(&token).await.is_none(),
        "a chain older than the newly-configured TTL must not renew"
    );

    cleanup(&pool, &sub).await;
}
