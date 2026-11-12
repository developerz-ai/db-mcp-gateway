use super::*;

#[tokio::test]
async fn global_cap_sheds_when_exhausted() {
    let limiter = ConcurrencyLimiter::with_limits(2, 8, 16);
    let p1 = limiter.try_global().expect("first permit");
    let _p2 = limiter.try_global().expect("second permit");
    assert!(limiter.try_global().is_none(), "third must shed");
    drop(p1);
    assert!(limiter.try_global().is_some(), "freed slot is reusable");
}

#[tokio::test]
async fn per_identity_cap_is_independent_across_users() {
    let limiter = ConcurrencyLimiter::with_limits(100, 1, 16);
    let alice = limiter
        .try_identity("alice", None)
        .await
        .expect("alice slot");
    assert!(
        limiter.try_identity("alice", None).await.is_none(),
        "alice is over her cap"
    );
    // Bob's cap is independent of alice's exhaustion.
    let _bob = limiter.try_identity("bob", None).await.expect("bob slot");
    drop(alice);
    assert!(
        limiter.try_identity("alice", None).await.is_some(),
        "freed alice slot is reusable"
    );
}

#[tokio::test]
async fn idle_identities_are_swept_when_map_is_full() {
    let limiter = ConcurrencyLimiter::with_limits(100, 2, 2);
    // Two identities go idle (acquired then released).
    drop(limiter.try_identity("alice", None).await.expect("alice"));
    drop(limiter.try_identity("bob", None).await.expect("bob"));
    // A third distinct identity triggers a sweep of the two idle entries.
    let _carol = limiter.try_identity("carol", None).await.expect("carol");
    let map = limiter.per_identity.lock().await;
    assert!(map.contains_key("carol"));
    assert!(
        map.len() <= limiter.max_tracked,
        "map stays bounded after sweep: {}",
        map.len()
    );
}

#[tokio::test]
async fn active_identities_survive_a_sweep() {
    let limiter = ConcurrencyLimiter::with_limits(100, 2, 1);
    // alice holds a permit → active, must not be swept when carol arrives.
    let _alice = limiter.try_identity("alice", None).await.expect("alice");
    let _carol = limiter.try_identity("carol", None).await.expect("carol");
    let map = limiter.per_identity.lock().await;
    assert!(
        map.contains_key("alice"),
        "active identity must survive sweep"
    );
}

/// The permit is taken under the map lock, so a sweep triggered by another
/// identity can never orphan a pool that is about to be used: alice's held
/// permit must keep counting against her single slot across any sweep.
#[tokio::test]
async fn a_sweep_never_splits_one_identity_across_two_pools() {
    let limiter = ConcurrencyLimiter::with_limits(100, 1, 1);
    let _alice = limiter.try_identity("alice", None).await.expect("alice");
    for other in ["bob", "carol", "dave"] {
        drop(limiter.try_identity(other, None).await);
    }
    assert!(
        limiter.try_identity("alice", None).await.is_none(),
        "alice's second concurrent request must still hit her cap"
    );
}

#[test]
fn oauth_budget_is_a_bounded_share_of_the_gated_cap() {
    assert_eq!(
        ConcurrencyLimiter::unauthenticated(512)
            .global
            .available_permits(),
        64
    );
    assert_eq!(
        ConcurrencyLimiter::unauthenticated(3)
            .global
            .available_permits(),
        1,
        "never zero: a tiny gated cap still admits one login"
    );
    assert_eq!(
        ConcurrencyLimiter::unauthenticated(512).global_scope,
        ShedScope::Oauth
    );
}

/// A service account's own cap replaces the per-identity default, so a fleet
/// behind one token is not throttled as one user.
#[tokio::test]
async fn account_cap_replaces_the_per_identity_default() {
    let limiter = ConcurrencyLimiter::with_limits(100, 1, 16);
    let held: Vec<_> = held_permits(&limiter, "service:fleet", Some(3)).await;
    assert_eq!(held.len(), 3, "the fleet gets its own cap of three");
    assert!(
        limiter
            .try_identity("service:fleet", Some(3))
            .await
            .is_none(),
        "the fourth is over the account cap"
    );
    let _alice = limiter.try_identity("alice", None).await.expect("alice");
    assert!(
        limiter.try_identity("alice", None).await.is_none(),
        "everyone else keeps the default of one"
    );
}

/// A reload that changes the account cap takes effect on the next request.
#[tokio::test]
async fn a_changed_account_cap_resizes_the_pool() {
    let limiter = ConcurrencyLimiter::with_limits(100, 1, 16);
    let _first = limiter
        .try_identity("service:fleet", Some(1))
        .await
        .expect("first");
    assert!(
        limiter
            .try_identity("service:fleet", Some(1))
            .await
            .is_none()
    );
    let raised = held_permits(&limiter, "service:fleet", Some(2)).await;
    assert_eq!(raised.len(), 2, "the raised cap admits two new requests");
}

async fn held_permits(
    limiter: &ConcurrencyLimiter,
    user_sub: &str,
    cap: Option<usize>,
) -> Vec<OwnedSemaphorePermit> {
    let mut held = Vec::new();
    while let Some(permit) = limiter.try_identity(user_sub, cap).await {
        held.push(permit);
        if held.len() > 64 {
            break;
        }
    }
    held
}
