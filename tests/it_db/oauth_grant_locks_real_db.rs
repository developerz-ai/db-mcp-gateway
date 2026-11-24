//! Lock order of every grant change, against the real state DB: subject
//! lock, then chain lock, then rows. Driven through the production
//! `RefreshTokens` calls — a call that stops taking the subject lock stops
//! waiting on one held here, and the test fails.
//!
//! Also `/revoke` against a rotation of the same token, held open at the
//! point where an unlocked revoke found its token gone and revoked nothing.
//! The same races run freely are in `oauth_grant_races_real_db`.
//!
//! `#[serial_test::parallel(world)]`: every test touches only rows of its own
//! uniquely-named subject.

use std::future::Future;
use std::time::{Duration, Instant};

use db_mcp_gateway::auth::oauth::RefreshTokens;
use db_mcp_gateway::state::oauth as db;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::common::env::state_pool;
use crate::oauth_revoke_race_real_db::{
    CHAIN_TTL, InFlightRotation, SESSION_TTL, chains_of, cleanup_sub, live_grants, mint_chain,
    session_store, token,
};

/// The subject lock of `sub`, held by this test in an open transaction.
struct HeldSubjectLock {
    tx: Transaction<'static, Postgres>,
    pid: i32,
}

impl HeldSubjectLock {
    async fn take(pool: &PgPool, sub: &str) -> Self {
        let mut tx = pool.begin().await.expect("begin");
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("pid");
        db::lock_subject(&mut *tx, sub).await.expect("lock subject");
        Self { tx, pid }
    }

    /// Run `call`, assert it blocks on this lock rather than finishing, then
    /// release the lock and return what the call answers.
    async fn release_once_waited_on<T: Send + 'static>(
        self,
        pool: &PgPool,
        call: impl Future<Output = T> + Send + 'static,
    ) -> T {
        let call: JoinHandle<T> = tokio::spawn(call);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let waited_on: bool = sqlx::query_scalar(
                "SELECT exists(SELECT 1 FROM pg_stat_activity \
                 WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(self.pid)
            .fetch_one(pool)
            .await
            .expect("blocking check");
            if waited_on {
                break;
            }
            assert!(
                !call.is_finished() && Instant::now() < deadline,
                "the call did not wait for the subject lock"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.tx.commit().await.expect("release the subject lock");
        call.await.expect("join")
    }
}

/// Age the chains' tombstones past `REUSE_GRACE`, so presenting a
/// rotated-out token is reuse rather than a client's own parallel refresh.
async fn age_tombstones(pool: &PgPool, chains: &[Uuid]) {
    sqlx::query(
        "UPDATE oauth_refresh_rotated SET rotated_at = now() - interval '1 minute' \
         WHERE chain_id = ANY($1)",
    )
    .bind(chains)
    .execute(pool)
    .await
    .expect("age tombstones");
}

pub(crate) struct Chain {
    pub(crate) pool: PgPool,
    pub(crate) store: RefreshTokens,
    pub(crate) sub: String,
    chains: Vec<Uuid>,
    /// The first token of the chain; rotated out when `rotated` is set.
    pub(crate) first: String,
}

impl Chain {
    /// A chain for a fresh subject. `rotated`: its first token has already
    /// been rotated out, long enough ago to count as reuse.
    pub(crate) async fn mint(tag: &str, rotated: bool) -> Self {
        let pool = state_pool().await;
        let sub = format!("{tag}-{}", Uuid::new_v4().simple());
        let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
        let first = mint_chain(&pool, &sub).await.refresh_token;
        let chains = chains_of(&pool, &sub).await;
        if rotated {
            store
                .rotate(&session_store(&pool), &first, token(), SESSION_TTL)
                .await
                .expect("rotate")
                .expect("first token is live");
            age_tombstones(&pool, &chains).await;
        }
        Self {
            pool,
            store,
            sub,
            chains,
            first,
        }
    }

    pub(crate) async fn assert_nothing_live_and_cleanup(self, context: &str) {
        assert_eq!(
            live_grants(&self.pool, &self.sub).await,
            (0, 0),
            "{context}: a session or refresh token is still live"
        );
        cleanup_sub(&self.pool, &self.sub, &self.chains).await;
    }
}

/// The production rotation takes the subject lock before it consumes the
/// token: started while the lock is held elsewhere, it waits.
#[tokio::test]
#[serial_test::parallel(world)]
async fn rotation_waits_for_the_subject_lock() {
    let chain = Chain::mint("lock-rotate", false).await;
    let held = HeldSubjectLock::take(&chain.pool, &chain.sub).await;
    let (store, sessions, first) = (
        chain.store.clone(),
        session_store(&chain.pool),
        chain.first.clone(),
    );
    let rotated = held
        .release_once_waited_on(&chain.pool, async move {
            store.rotate(&sessions, &first, token(), SESSION_TTL).await
        })
        .await;

    assert!(rotated.expect("rotation").is_some(), "a live token rotates");
    assert_eq!(live_grants(&chain.pool, &chain.sub).await, (1, 1));
    cleanup_sub(&chain.pool, &chain.sub, &chain.chains).await;
}

/// Reuse revocation writes the subject's session and token rows, so it
/// takes the subject lock first, like logout.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_replayed_token_waits_for_the_subject_lock() {
    let chain = Chain::mint("lock-replay", true).await;
    let held = HeldSubjectLock::take(&chain.pool, &chain.sub).await;
    let (store, sessions, first) = (
        chain.store.clone(),
        session_store(&chain.pool),
        chain.first.clone(),
    );
    let replayed = held
        .release_once_waited_on(&chain.pool, async move {
            store.rotate(&sessions, &first, token(), SESSION_TTL).await
        })
        .await;

    assert!(replayed.expect("replay is not an error").is_none());
    chain.assert_nothing_live_and_cleanup("replay").await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn revoke_waits_for_the_subject_lock() {
    let chain = Chain::mint("lock-revoke", false).await;
    let held = HeldSubjectLock::take(&chain.pool, &chain.sub).await;
    let (store, sessions, first) = (
        chain.store.clone(),
        session_store(&chain.pool),
        chain.first.clone(),
    );
    let revoked = held
        .release_once_waited_on(
            &chain.pool,
            async move { store.revoke(&sessions, &first).await },
        )
        .await;

    assert!(revoked.expect("revoke"), "a live refresh token was revoked");
    chain.assert_nothing_live_and_cleanup("revoke").await;
}

/// `/revoke` starts while a rotation has consumed the presented token and
/// written the new pair but not committed. It must wait and then end the
/// new pair, not find its token gone and revoke nothing.
#[tokio::test]
#[serial_test::parallel(world)]
async fn revoke_during_an_in_flight_rotation_ends_the_new_pair() {
    let pool = state_pool().await;
    let sub = format!("revoke-rotate-{}", Uuid::new_v4().simple());
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let first = mint_chain(&pool, &sub).await;
    let chains = chains_of(&pool, &sub).await;

    let rotation = InFlightRotation::begin(&pool, &sub, &first).await;
    let revoke = {
        let (sessions, presented) = (session_store(&pool), first.refresh_token.clone());
        tokio::spawn(async move { store.revoke(&sessions, &presented).await })
    };
    rotation.commit_once_blocking(&pool).await;

    assert!(revoke.await.expect("join").expect("revoke succeeds"));
    assert_eq!(
        live_grants(&pool, &sub).await,
        (0, 0),
        "the rotated pair survived the revoke"
    );
    cleanup_sub(&pool, &sub, &chains).await;
}

/// The same race lost the other way: the rotation committed first, so the
/// presented token is only a tombstone. Revoking it still ends its chain.
#[tokio::test]
#[serial_test::parallel(world)]
async fn revoking_a_rotated_out_token_ends_its_chain() {
    let chain = Chain::mint("revoke-rotated", true).await;
    let sessions = session_store(&chain.pool);

    assert!(
        chain
            .store
            .revoke(&sessions, &chain.first)
            .await
            .expect("revoke"),
        "a rotated-out refresh token is still a refresh token"
    );
    chain.assert_nothing_live_and_cleanup("revoke").await;
}

/// A token that never was a refresh token is not claimed as one, so
/// `/revoke` goes on to try it as a session JWT.
#[tokio::test]
#[serial_test::parallel(world)]
async fn revoking_an_unknown_token_reports_no_refresh_token() {
    let pool = state_pool().await;
    let store = RefreshTokens::with_db(pool.clone(), CHAIN_TTL);
    let revoked = store.revoke(&session_store(&pool), &token()).await;
    assert!(!revoked.expect("revoke"));
}
