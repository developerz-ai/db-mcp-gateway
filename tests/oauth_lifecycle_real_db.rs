//! Real-DB lifecycle tests for the OAuth bridge stores (issue #314 slice B).
//!
//! `#[serial]` and only ever touching its own uniquely-named rows, so it can't
//! disturb `client_registry_real_db.rs`'s cap seeding.

mod common;

use std::time::Duration;

use common::env::state_pool;
use db_mcp_gateway::auth::oauth::{ClientRegistry, GrantIdentity, RefreshTokens};
use db_mcp_gateway::auth::{AuthError, SessionCacheConfig, SessionStore};
use db_mcp_gateway::state::oauth::{self as db, NewRefreshToken};
use serial_test::serial;
use sqlx::PgPool;

const CHAIN_TTL: Duration = Duration::from_secs(24 * 3600);
const SESSION_TTL: Duration = Duration::from_secs(3600);

async fn cleanup(pool: &PgPool, client_id: &str) {
    sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(pool)
        .await
        .expect("cleanup");
}

/// A client caches a `client_id` whose registration lapsed but the GC hasn't
/// swept yet; `/authorize` adopts it. Adoption must revive the row — before
/// the fix the upsert kept the lapsed `expires_at`, the lookup filtered it
/// out, and every retry 503'd until GC ran.
#[tokio::test]
#[serial]
async fn adopting_a_lapsed_unswept_client_revives_it() {
    let pool = state_pool().await;
    let client_id = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &client_id).await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, created_at, expires_at) \
         VALUES ($1, '[\"http://127.0.0.1:1/old\"]'::jsonb, \
                 now() - interval '91 days', now() - interval '1 day')",
    )
    .bind(&client_id)
    .execute(&pool)
    .await
    .expect("seed lapsed row");

    let reg = ClientRegistry::with_db(pool.clone());
    reg.adopt(client_id.clone(), "http://127.0.0.1:2/cb".into())
        .await
        .expect("adoption revives a lapsed registration");
    assert_eq!(
        reg.redirect_uris(&client_id).await,
        Some(vec!["http://127.0.0.1:2/cb".into()])
    );
    let promoted: bool = sqlx::query_scalar(
        "SELECT expires_at > now() + interval '89 days' FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&pool)
    .await
    .expect("read expiry");
    assert!(promoted, "adopted client carries the full authorised TTL");

    cleanup(&pool, &client_id).await;
}

/// Only a lapsed row is reset: re-registering a live client keeps its expiry.
#[tokio::test]
#[serial]
async fn re_registering_a_live_client_keeps_its_expiry() {
    let pool = state_pool().await;
    let client_id = format!("mcp-test-{}", uuid::Uuid::new_v4().simple());
    cleanup(&pool, &client_id).await;

    let reg = ClientRegistry::with_db(pool.clone());
    reg.adopt(client_id.clone(), "http://127.0.0.1:2/cb".into())
        .await
        .expect("adopted");
    let expiry = "SELECT expires_at FROM oauth_clients WHERE client_id = $1";
    let before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(expiry)
        .bind(&client_id)
        .fetch_one(&pool)
        .await
        .expect("read expiry");
    reg.insert(client_id.clone(), vec!["https://other/cb".into()])
        .await
        .expect("re-registered");
    let after: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(expiry)
        .bind(&client_id)
        .fetch_one(&pool)
        .await
        .expect("read expiry");
    assert_eq!(before, after);

    cleanup(&pool, &client_id).await;
}

fn identity(sub: &str) -> GrantIdentity {
    GrantIdentity {
        sub: sub.to_string(),
        email: format!("{sub}@example.com"),
        groups: vec!["engineers".into()],
    }
}

fn token() -> String {
    format!("tok-{}", uuid::Uuid::new_v4().simple())
}

/// Zero cache TTL: every lookup re-reads the DB, so asserts see committed state.
fn session_store(pool: &PgPool) -> SessionStore {
    SessionStore::with_cache_config(
        pool.clone(),
        SessionCacheConfig {
            ttl: Duration::ZERO,
            max_entries: 100,
        },
    )
}

/// The sub's chain ids, captured while the chains are still live: once reuse
/// revokes a chain, only its tombstones remember the id.
async fn chains_of(pool: &PgPool, sub: &str) -> Vec<uuid::Uuid> {
    sqlx::query_scalar("SELECT chain_id FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(sub)
        .fetch_all(pool)
        .await
        .expect("chain ids")
}

/// Backdate the chains' tombstones by `secs`, to land a replay on either
/// side of the reuse grace without sleeping.
async fn age_tombstones(pool: &PgPool, chains: &[uuid::Uuid], secs: f64) {
    sqlx::query(
        "UPDATE oauth_refresh_rotated SET rotated_at = now() - make_interval(secs => $2) \
         WHERE chain_id = ANY($1)",
    )
    .bind(chains)
    .bind(secs)
    .execute(pool)
    .await
    .expect("age tombstones");
}

async fn cleanup_sub(pool: &PgPool, sub: &str, chains: &[uuid::Uuid]) {
    sqlx::query("DELETE FROM oauth_refresh_rotated WHERE chain_id = ANY($1)")
        .bind(chains)
        .execute(pool)
        .await
        .expect("cleanup tombstones");
    for table in ["oauth_refresh_tokens", "sessions"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_sub = $1"))
            .bind(sub)
            .execute(pool)
            .await
            .expect("cleanup");
    }
}

/// RFC 9700 §4.14.2: a thief rotates a stolen refresh token first. When the
/// legitimate client then presents the (now rotated-out) original, the whole
/// chain dies — the thief's fresh token and its session included.
#[tokio::test]
#[serial]
async fn reusing_a_rotated_refresh_token_revokes_the_chain() {
    let pool = state_pool().await;
    let sub = format!("rt-reuse-{}", uuid::Uuid::new_v4().simple());
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let sessions = session_store(&pool);

    let stolen = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let thief = store
        .rotate(&sessions, &stolen.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate")
        .expect("thief rotates first");

    let chains = chains_of(&pool, &sub).await;
    // Past the 10 s grace: a replay now can't be the client's own parallel call.
    age_tombstones(&pool, &chains, 11.0).await;

    let reuse = store
        .rotate(&sessions, &stolen.refresh_token, token(), SESSION_TTL)
        .await
        .expect("reuse is not a server error");
    assert!(reuse.is_none(), "a rotated-out token is invalid_grant");

    let thief_refresh = store
        .rotate(&sessions, &thief.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate");
    assert!(thief_refresh.is_none(), "reuse ended the thief's chain");
    let thief_session = sessions.lookup(thief.session.id).await;
    assert!(
        matches!(thief_session, Err(AuthError::RevokedSession)),
        "reuse revoked the chain's live session, got {thief_session:?}"
    );

    cleanup_sub(&pool, &sub, &chains).await;
}

/// A client's parallel refreshes replay one token within moments of its
/// rotation: just `invalid_grant`, and the winning call's new token and
/// session stay live — no forced re-login.
#[tokio::test]
#[serial]
async fn replay_inside_the_grace_keeps_the_chain() {
    let pool = state_pool().await;
    let sub = format!("rt-grace-{}", uuid::Uuid::new_v4().simple());
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let sessions = session_store(&pool);

    let first = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let chains = chains_of(&pool, &sub).await;
    let winner = store
        .rotate(&sessions, &first.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate")
        .expect("first call rotates");
    // Just inside the 10 s grace.
    age_tombstones(&pool, &chains, 9.0).await;

    let parallel = store
        .rotate(&sessions, &first.refresh_token, token(), SESSION_TTL)
        .await
        .expect("replay is not a server error");
    assert!(
        parallel.is_none(),
        "the losing parallel call is invalid_grant"
    );
    assert!(sessions.lookup(winner.session.id).await.is_ok());
    let next = store
        .rotate(&sessions, &winner.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate");
    assert!(next.is_some(), "the winner's token still rotates");

    cleanup_sub(&pool, &sub, &chains).await;
}

/// Reuse detection must not reach across chains: one user's replay leaves a
/// sibling chain (another device, same `sub`) alive.
#[tokio::test]
#[serial]
async fn reuse_revokes_only_its_own_chain() {
    let pool = state_pool().await;
    let sub = format!("rt-sibling-{}", uuid::Uuid::new_v4().simple());
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let sessions = session_store(&pool);

    let laptop = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let desktop = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let chains = chains_of(&pool, &sub).await;
    store
        .rotate(&sessions, &laptop.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate")
        .expect("live");
    age_tombstones(&pool, &chains, 11.0).await;
    store
        .rotate(&sessions, &laptop.refresh_token, token(), SESSION_TTL)
        .await
        .expect("reuse");

    assert!(sessions.lookup(desktop.session.id).await.is_ok());
    let desktop_refresh = store
        .rotate(&sessions, &desktop.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate");
    assert!(desktop_refresh.is_some(), "sibling chain untouched");

    cleanup_sub(&pool, &sub, &chains).await;
}

/// GC sweeps lapsed tombstones along with lapsed chains.
#[tokio::test]
#[serial]
async fn gc_sweeps_lapsed_tombstones() {
    let pool = state_pool().await;
    let chain = uuid::Uuid::new_v4();
    let hash = uuid::Uuid::new_v4().as_bytes().to_vec();
    sqlx::query(
        "INSERT INTO oauth_refresh_rotated (token_hash, chain_id, expires_at) \
         VALUES ($1, $2, now() - interval '1 second')",
    )
    .bind(&hash)
    .bind(chain)
    .execute(&pool)
    .await
    .expect("seed lapsed tombstone");

    RefreshTokens::with_db(pool.clone(), CHAIN_TTL)
        .gc_expired()
        .await;
    let left: bool = sqlx::query_scalar(
        "SELECT exists(SELECT 1 FROM oauth_refresh_rotated WHERE chain_id = $1)",
    )
    .bind(chain)
    .fetch_one(&pool)
    .await
    .expect("existence check");
    assert!(!left, "GC removed the lapsed tombstone");
}

/// Race: the thief's rotation T2 → T3 is mid-transaction when the victim
/// replays T1. The revocation must wait for it and then end T3 too — under
/// READ COMMITTED a bare `DELETE … WHERE chain_id` waits on T2's row lock,
/// re-checks only T2 (now gone) and never sees T3.
#[tokio::test]
#[serial]
async fn reuse_revocation_waits_for_an_in_flight_rotation() {
    let pool = state_pool().await;
    let sub = format!("rt-race-{}", uuid::Uuid::new_v4().simple());
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let sessions = session_store(&pool);

    let t1 = store
        .mint(&sessions, identity(&sub), token(), SESSION_TTL)
        .await
        .expect("mint");
    let chains = chains_of(&pool, &sub).await;
    let chain = chains[0];
    let t2 = store
        .rotate(&sessions, &t1.refresh_token, token(), SESSION_TTL)
        .await
        .expect("rotate")
        .expect("live");
    age_tombstones(&pool, &chains, 11.0).await;

    // Tx B: the thief's rotation of T2, statement for statement as `rotate`
    // runs it, held open.
    let mut thief = pool.begin().await.expect("begin B");
    let thief_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *thief)
        .await
        .expect("pid");
    let t2_hash: [u8; 32] =
        <sha2::Sha256 as sha2::Digest>::digest(t2.refresh_token.as_bytes()).into();
    db::lock_chain(&mut *thief, chain).await.expect("lock");
    db::rotate_out_refresh_token(&mut *thief, &t2_hash)
        .await
        .expect("rotate out T2")
        .expect("T2 live");
    let t3_hash = [3u8; 32];
    let born = t1.session.issued_at;
    db::insert_refresh_token_capped(
        &mut *thief,
        &NewRefreshToken {
            token_hash: &t3_hash,
            user_sub: &sub,
            email: "x@example.com",
            groups: &[],
            chain_issued_at: born,
            expires_at: born + chrono::Duration::hours(24),
            session_id: None,
            chain_id: chain,
        },
        i64::MAX,
    )
    .await
    .expect("insert T3");

    // Tx A: the victim replays T1 and blocks behind B.
    let victim = {
        let (store, sessions, t1) = (store.clone(), sessions.clone(), t1.refresh_token.clone());
        tokio::spawn(async move { store.rotate(&sessions, &t1, token(), SESSION_TTL).await })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT exists(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(thief_pid)
        .fetch_one(&pool)
        .await
        .expect("blocking check");
        if blocked {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "victim never blocked on B"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    thief.commit().await.expect("commit B");

    let replay = victim.await.expect("join").expect("replay is not an error");
    assert!(replay.is_none());
    let live: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_refresh_tokens WHERE chain_id = $1")
            .bind(chain)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(live, 0, "the thief's in-flight T3 must be revoked too");

    cleanup_sub(&pool, &sub, &chains).await;
}
