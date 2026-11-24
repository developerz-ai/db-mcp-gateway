//! Grant changes of one subject racing each other for real, many rounds
//! each: a replayed token against logout (a deadlock, and a 500, when the
//! replay locked only the chain), and RFC 7009 `/revoke` against a rotation
//! of the same token (the rotated pair survived when `/revoke` took no
//! lock). The lock order itself is pinned deterministically in
//! `oauth_grant_locks_real_db`.
//!
//! `#[serial_test::parallel(world)]`: every round touches only rows of its
//! own uniquely-named subject.

use std::future::Future;
use std::sync::Arc;

use crate::oauth_grant_locks_real_db::Chain;
use crate::oauth_revoke_race_real_db::{SESSION_TTL, session_store, token};

/// Run `left` and `right` from one barrier, so they overlap.
async fn race<L, R>(
    left: impl Future<Output = L> + Send + 'static,
    right: impl Future<Output = R> + Send + 'static,
) -> (L, R)
where
    L: Send + 'static,
    R: Send + 'static,
{
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let (first, second) = (barrier.clone(), barrier);
    let left = tokio::spawn(async move {
        first.wait().await;
        left.await
    });
    let right = tokio::spawn(async move {
        second.wait().await;
        right.await
    });
    (left.await.expect("join"), right.await.expect("join"))
}

/// A replayed token racing logout, many times: both write the subject's
/// session and token rows, so without one lock order they deadlock and one
/// of them answers 500.
#[tokio::test]
#[serial_test::parallel(world)]
async fn concurrent_replay_and_logout_never_deadlock() {
    for round in 0..60 {
        let chain = Chain::mint("replay-logout", true).await;
        let sessions = session_store(&chain.pool);
        let replay = {
            let (store, sessions, first) =
                (chain.store.clone(), sessions.clone(), chain.first.clone());
            async move { store.rotate(&sessions, &first, token(), SESSION_TTL).await }
        };
        let logout = {
            let (store, sub) = (chain.store.clone(), chain.sub.clone());
            async move { store.end_all_for_sub(&sessions, &sub).await }
        };
        let (replayed, logged_out) = race(replay, logout).await;

        assert!(
            replayed
                .unwrap_or_else(|err| panic!("round {round}: replay failed: {err}"))
                .is_none()
        );
        logged_out.unwrap_or_else(|err| panic!("round {round}: logout failed: {err}"));
        chain
            .assert_nothing_live_and_cleanup(&format!("round {round}"))
            .await;
    }
}

/// The real `/revoke` racing the real rotation of the same token, many
/// times: whichever commits first, the chain ends with nothing live.
#[tokio::test]
#[serial_test::parallel(world)]
async fn concurrent_revoke_and_rotation_never_leave_a_live_grant() {
    for round in 0..60 {
        let chain = Chain::mint("revoke-race", false).await;
        let sessions = session_store(&chain.pool);
        let rotate = {
            let (store, sessions, first) =
                (chain.store.clone(), sessions.clone(), chain.first.clone());
            async move { store.rotate(&sessions, &first, token(), SESSION_TTL).await }
        };
        let revoke = {
            let (store, first) = (chain.store.clone(), chain.first.clone());
            async move { store.revoke(&sessions, &first).await }
        };
        let (rotated, revoked) = race(rotate, revoke).await;

        rotated.unwrap_or_else(|err| panic!("round {round}: rotation failed: {err}"));
        assert!(
            revoked.unwrap_or_else(|err| panic!("round {round}: revoke failed: {err}")),
            "round {round}: the presented token was not recognised"
        );
        chain
            .assert_nothing_live_and_cleanup(&format!("round {round}"))
            .await;
    }
}
