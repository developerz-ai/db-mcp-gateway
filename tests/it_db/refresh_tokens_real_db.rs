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

use crate::common::env::state_pool;
use db_mcp_gateway::auth::oauth::{GrantIdentity, RefreshTokens};
use db_mcp_gateway::auth::{AuthError, SessionStore};
use sqlx::PgPool;

const TTL: Duration = Duration::from_secs(60 * 24 * 3600);
const SESSION_TTL: Duration = Duration::from_secs(3600);

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
    for table in ["oauth_refresh_tokens", "sessions"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_sub = $1"))
            .bind(sub)
            .execute(pool)
            .await
            .expect("cleanup");
    }
}

fn token() -> String {
    format!("tok-{}", uuid::Uuid::new_v4().simple())
}

/// Every session store over the pool; a zero TTL makes each lookup re-read
/// the DB, so assertions see committed state, not this process's cache.
fn session_store(pool: &PgPool) -> SessionStore {
    SessionStore::with_cache_config(
        pool.clone(),
        db_mcp_gateway::auth::SessionCacheConfig {
            ttl: Duration::ZERO,
            max_entries: 100,
        },
    )
}

/// The regression this table exists for: a chain minted before a restart still
/// renews after it, carrying the identity (groups included) it was minted with.
#[tokio::test]
async fn chain_survives_a_restart() {
    let pool = state_pool().await;
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
    let pool = state_pool().await;
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
    let pool = state_pool().await;
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
    let pool = state_pool().await;
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
    let pool = state_pool().await;
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
    let pool = state_pool().await;
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

/// Rotation revokes the session paired with the redeemed token: after a
/// refresh, the previous access token no longer authenticates.
#[tokio::test]
async fn rotation_revokes_the_previous_session() {
    let pool = state_pool().await;
    let sub = unique_sub("pair");
    let store = RefreshTokens::with_db(pool.clone(), TTL);
    let sessions = session_store(&pool);

    let first = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let second = store
        .rotate(&sessions, &first.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate")
        .expect("live token rotates");

    let old = session_store(&pool).lookup(first.session.id).await;
    assert!(matches!(old, Err(AuthError::RevokedSession)), "got {old:?}");
    assert!(session_store(&pool).lookup(second.session.id).await.is_ok());
    // The DB stores microseconds; the in-memory first stamp has nanoseconds.
    let drift = second.session.issued_at - first.session.issued_at;
    assert!(
        drift.num_microseconds().is_some_and(|us| us.abs() < 1),
        "the new session keeps the original login time, drift {drift}"
    );
    let replay = store
        .rotate(&sessions, &first.refresh_token, token(), SESSION_TTL)
        .await
        .expect("replay is not an error");
    assert!(replay.is_none(), "a rotated token must not renew twice");

    cleanup(&pool, &sub).await;
}

/// A rotation that fails part-way commits nothing: the presented token and its
/// session stay usable, so a transient error is not a sign-out.
#[tokio::test]
async fn failed_rotation_leaves_the_old_chain_usable() {
    let pool = state_pool().await;
    let sub = unique_sub("rollback");
    let sessions = session_store(&pool);
    let first = RefreshTokens::with_db(pool.clone(), TTL)
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");

    // An unrepresentable chain TTL makes the new refresh row violate its CHECK
    // after the old row was deleted and the old session revoked in the tx.
    let broken = RefreshTokens::with_db(pool.clone(), Duration::MAX);
    let result = broken
        .rotate(&sessions, &first.refresh_token, token(), SESSION_TTL)
        .await;
    assert!(matches!(result, Err(AuthError::State(_))), "got {result:?}");

    assert!(
        sessions.lookup(first.session.id).await.is_ok(),
        "old session live"
    );
    let retried = RefreshTokens::with_db(pool.clone(), TTL)
        .rotate(&sessions, &first.refresh_token, token(), SESSION_TTL)
        .await
        .expect("retry");
    assert!(retried.is_some(), "old refresh token still redeemable");

    cleanup(&pool, &sub).await;
}

/// RFC 7009 on a refresh token ends the chain and its paired access session.
#[tokio::test]
async fn revoking_a_refresh_token_revokes_its_session() {
    let pool = state_pool().await;
    let sub = unique_sub("revoke");
    let store = RefreshTokens::with_db(pool.clone(), TTL);
    let sessions = session_store(&pool);
    let minted = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");

    assert!(
        store
            .revoke(&sessions, &minted.refresh_token)
            .await
            .expect("revoke")
    );
    let lookup = sessions.lookup(minted.session.id).await;
    assert!(
        matches!(lookup, Err(AuthError::RevokedSession)),
        "got {lookup:?}"
    );
    assert!(
        !store
            .revoke(&sessions, &minted.refresh_token)
            .await
            .expect("revoke"),
        "an unknown token is reported as not revoked"
    );

    cleanup(&pool, &sub).await;
}

/// Logout ends every session and chain of the identity, not just the caller's.
#[tokio::test]
async fn end_all_for_sub_leaves_no_live_bearer() {
    let pool = state_pool().await;
    let sub = unique_sub("logout");
    let theirs = unique_sub("logout-theirs");
    let store = RefreshTokens::with_db(pool.clone(), TTL);
    let sessions = session_store(&pool);
    let laptop = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let phone = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let other = store
        .mint(&sessions, identity(&theirs), token(), SESSION_TTL)
        .await
        .expect("mint");

    assert_eq!(
        store
            .end_all_for_sub(&sessions, &sub)
            .await
            .expect("logout"),
        2
    );
    for minted in [&laptop, &phone] {
        assert!(sessions.lookup(minted.session.id).await.is_err());
        assert!(store.take(&minted.refresh_token).await.is_none());
    }
    assert!(
        sessions.lookup(other.session.id).await.is_ok(),
        "others untouched"
    );

    cleanup(&pool, &sub).await;
    cleanup(&pool, &theirs).await;
}

/// A closed state pool is an error the caller can report, never a silent
/// "nothing to revoke".
#[tokio::test]
async fn revoke_with_closed_pool_is_an_error() {
    let pool = state_pool().await;
    let sessions = session_store(&pool);
    let store = RefreshTokens::with_db(pool.clone(), TTL);
    pool.close().await;
    let result = store.revoke(&sessions, &token()).await;
    assert!(matches!(result, Err(AuthError::State(_))), "got {result:?}");
}
