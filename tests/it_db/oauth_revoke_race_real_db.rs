//! Real-DB races between a refresh rotation and a subject-wide revocation
//! (logout, admin `revoke-sessions`). Whichever commits first, the subject
//! must end with no live session and no refresh token: a rotation's new pair
//! must not slip past a revocation that overlapped it.
//!
//! `#[serial_test::parallel(world)]`: every test touches only rows of its own
//! uniquely-named subject.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::env::state_pool;
use db_mcp_gateway::auth::oauth::{GrantIdentity, Minted, RefreshTokens};
use db_mcp_gateway::auth::{SessionCacheConfig, SessionStore};
use db_mcp_gateway::state::oauth::{self as db, NewRefreshToken};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub(crate) const CHAIN_TTL: Duration = Duration::from_secs(24 * 3600);
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(3600);

pub(crate) fn identity(sub: &str) -> GrantIdentity {
    GrantIdentity {
        sub: sub.to_string(),
        email: format!("{sub}@example.com"),
        groups: vec!["engineers".into()],
    }
}

pub(crate) fn token() -> String {
    format!("tok-{}", Uuid::new_v4().simple())
}

/// Zero cache TTL: every lookup re-reads the DB, so asserts see committed state.
pub(crate) fn session_store(pool: &PgPool) -> SessionStore {
    SessionStore::with_cache_config(
        pool.clone(),
        SessionCacheConfig {
            ttl: Duration::ZERO,
            max_entries: 100,
        },
    )
}

/// A fresh session + refresh chain for `sub`, as a code redemption mints it.
pub(crate) async fn mint_chain(pool: &PgPool, sub: &str) -> Minted {
    RefreshTokens::with_db(pool.clone(), CHAIN_TTL)
        .mint(&session_store(pool), identity(sub), token(), SESSION_TTL)
        .await
        .expect("mint")
}

/// `(live sessions, refresh tokens)` still held by `sub`.
pub(crate) async fn live_grants(pool: &PgPool, sub: &str) -> (i64, i64) {
    let sessions = sqlx::query_scalar(
        "SELECT count(*) FROM sessions \
         WHERE user_sub = $1 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(sub)
    .fetch_one(pool)
    .await
    .expect("count sessions");
    let tokens =
        sqlx::query_scalar("SELECT count(*) FROM oauth_refresh_tokens WHERE user_sub = $1")
            .bind(sub)
            .fetch_one(pool)
            .await
            .expect("count tokens");
    (sessions, tokens)
}

/// The sub's chain ids, read while the chains are live: once they are
/// revoked only their tombstones remember the id.
pub(crate) async fn chains_of(pool: &PgPool, sub: &str) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT chain_id FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(sub)
        .fetch_all(pool)
        .await
        .expect("chain ids")
}

pub(crate) async fn cleanup_sub(pool: &PgPool, sub: &str, chains: &[Uuid]) {
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

/// A refresh rotation of `sub`'s chain run statement for statement as
/// `RefreshTokens::rotate` runs it, but held open before its commit so a
/// test can start a revocation in the middle of it. That the production
/// rotation takes these locks itself is pinned in
/// `oauth_grant_locks_real_db`, which blocks the real call on a held lock.
pub(crate) struct InFlightRotation {
    tx: Transaction<'static, Postgres>,
    pid: i32,
}

impl InFlightRotation {
    pub(crate) async fn begin(pool: &PgPool, sub: &str, current: &Minted) -> Self {
        let mut tx = pool.begin().await.expect("begin rotation");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("pid");
        let hash: [u8; 32] =
            <sha2::Sha256 as sha2::Digest>::digest(current.refresh_token.as_bytes()).into();
        let (locked_sub, chain_id) = db::live_chain(&mut *tx, &hash)
            .await
            .expect("live chain")
            .expect("current token is live");
        db::lock_subject(&mut *tx, &locked_sub)
            .await
            .expect("lock subject");
        db::lock_chain(&mut *tx, chain_id)
            .await
            .expect("lock chain");
        let old = db::rotate_out_refresh_token(&mut *tx, &hash)
            .await
            .expect("rotate out")
            .expect("current token is live");
        SessionStore::revoke_in(&mut tx, current.session.id)
            .await
            .expect("revoke the paired session");
        let born = current.session.issued_at;
        let next = SessionStore::prepare(sub, "x@example.com", &[], SESSION_TTL, Some(born));
        SessionStore::insert_in(&mut tx, &next)
            .await
            .expect("insert the next session");
        db::insert_refresh_token_capped(
            &mut *tx,
            &NewRefreshToken {
                token_hash: Uuid::new_v4().as_bytes(),
                user_sub: sub,
                email: "x@example.com",
                groups: &[],
                chain_issued_at: born,
                expires_at: born + chrono::Duration::hours(24),
                session_id: Some(Uuid::from(next.id)),
                chain_id: old.chain_id,
            },
            i64::MAX,
        )
        .await
        .expect("insert the next token");
        Self { tx, pid }
    }

    /// Commit once some other backend is waiting on this transaction — i.e.
    /// the revocation under test has started and is blocked behind it.
    pub(crate) async fn commit_once_blocking(self, pool: &PgPool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let blocking: bool = sqlx::query_scalar(
                "SELECT exists(SELECT 1 FROM pg_stat_activity \
                 WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(self.pid)
            .fetch_one(pool)
            .await
            .expect("blocking check");
            if blocking {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the revocation never waited on the in-flight rotation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.tx.commit().await.expect("commit rotation");
    }
}

/// Logout starts while a rotation has consumed the old token and written the
/// new pair but not yet committed. Logout must wait for it and then end the
/// new session and token as well.
#[tokio::test]
#[serial_test::parallel(world)]
async fn logout_during_an_in_flight_rotation_ends_the_new_pair() {
    let pool = state_pool().await;
    let sub = format!("rt-logout-race-{}", Uuid::new_v4().simple());
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let sessions = session_store(&pool);
    let first = mint_chain(&pool, &sub).await;
    let chains = chains_of(&pool, &sub).await;

    let rotation = InFlightRotation::begin(&pool, &sub, &first).await;
    let logout = {
        let (store, sessions, sub) = (store.clone(), sessions.clone(), sub.clone());
        tokio::spawn(async move { store.end_all_for_sub(&sessions, &sub).await })
    };
    rotation.commit_once_blocking(&pool).await;
    logout.await.expect("join").expect("logout succeeds");

    assert_eq!(
        live_grants(&pool, &sub).await,
        (0, 0),
        "logout left a live session or refresh token behind"
    );

    cleanup_sub(&pool, &sub, &chains).await;
}

/// The real rotation racing the real logout, many times: every interleaving
/// must leave the subject with nothing live, and neither call may error
/// (no deadlock between the two).
#[tokio::test]
#[serial_test::parallel(world)]
async fn concurrent_rotation_and_logout_never_leave_a_live_grant() {
    let pool = state_pool().await;
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let sessions = session_store(&pool);

    for round in 0..60 {
        let sub = format!("rt-race-{round}-{}", Uuid::new_v4().simple());
        let first = mint_chain(&pool, &sub).await;
        let chains = chains_of(&pool, &sub).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let rotate = {
            let (store, sessions, barrier) = (store.clone(), sessions.clone(), barrier.clone());
            let presented = first.refresh_token.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .rotate(&sessions, &presented, token(), SESSION_TTL)
                    .await
            })
        };
        let logout = {
            let (store, sessions, barrier) = (store.clone(), sessions.clone(), barrier.clone());
            let sub = sub.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.end_all_for_sub(&sessions, &sub).await
            })
        };
        let rotated = rotate
            .await
            .expect("join")
            .expect("rotation is not an error");
        logout.await.expect("join").expect("logout succeeds");

        assert_eq!(
            live_grants(&pool, &sub).await,
            (0, 0),
            "round {round}: a grant survived logout"
        );
        if let Some(minted) = rotated {
            assert!(
                sessions.lookup(minted.session.id).await.is_err(),
                "round {round}: the rotated session still authenticates"
            );
        }
        cleanup_sub(&pool, &sub, &chains).await;
    }
}
