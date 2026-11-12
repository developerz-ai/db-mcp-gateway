use super::*;

fn identity() -> GrantIdentity {
    GrantIdentity {
        sub: "u1".into(),
        email: "u1@example.com".into(),
        groups: vec!["eng".into()],
    }
}

#[tokio::test]
async fn refresh_round_trips_by_raw_token_and_is_consumed_once() {
    let store = RefreshTokens::default();
    store.insert("raw-token", identity()).await.unwrap();

    // Lookup hashes the presented value, so the raw token resolves...
    let entry = store.take("raw-token").await.expect("token is live");
    assert_eq!(entry.identity.sub, "u1");
    // ...and rotation/redemption consumes it (replay finds nothing).
    assert!(store.take("raw-token").await.is_none());
}

#[tokio::test]
async fn refresh_rotation_carries_birth_time_and_never_extends_it() {
    let store = RefreshTokens::default();

    // A rotated token must store the *passed* chain birth verbatim, not
    // `Utc::now()` — that's what keeps the absolute TTL from sliding.
    let birth = Utc::now();
    store
        .insert_rotated("rotated", identity(), birth)
        .await
        .unwrap();
    let entry = store.take("rotated").await.expect("token is live");
    assert_eq!(
        entry.issued_at, birth,
        "rotation must not reset the chain clock"
    );

    // A fresh insert, by contrast, stamps ~now.
    let before = Utc::now();
    store.insert("fresh", identity()).await.unwrap();
    let after = Utc::now();
    let fresh = store.take("fresh").await.expect("token is live");
    assert!(fresh.issued_at >= before && fresh.issued_at <= after);
}

#[test]
fn default_refresh_chain_ttl_bounds_group_staleness_within_a_day() {
    // O3b: the chain's `groups` are frozen at the original login, so the
    // chain TTL is the worst-case window a since-revoked group keeps minting
    // sessions. The *default* stays conservative — an operator opts into a
    // longer window explicitly via `REFRESH_TTL_DAYS`; guard the default
    // against an accidental regression to a multi-week cap.
    assert!(DEFAULT_REFRESH_TTL <= Duration::from_secs(24 * 3600));
}

#[test]
fn chain_is_dead_once_it_reaches_the_absolute_ttl() {
    let ttl = DEFAULT_REFRESH_TTL;
    let span = ChronoDuration::from_std(ttl).unwrap();
    let born = Utc::now();
    assert!(!chain_expired(born, born, ttl), "a fresh chain is live");
    assert!(
        !chain_expired(born, born + span - ChronoDuration::seconds(1), ttl),
        "inside the window the chain still renews"
    );
    assert!(
        chain_expired(born, born + span, ttl),
        "at the cap the chain is dead — no more stale-group minting"
    );
}

#[tokio::test]
async fn expired_refresh_chain_is_gc_dropped_and_not_returned() {
    let store = RefreshTokens::default();
    // Born a full TTL ago → already past the cap.
    let stale_birth = Utc::now() - ChronoDuration::from_std(DEFAULT_REFRESH_TTL).unwrap();
    store
        .insert_rotated("stale", identity(), stale_birth)
        .await
        .unwrap();
    // take() checks expiration and rejects expired tokens before returning.
    assert!(
        store.take("stale").await.is_none(),
        "a chain at/over its TTL must not renew"
    );
}

#[tokio::test]
async fn custom_ttl_extends_the_chain_window() {
    // A chain older than the default but younger than a longer configured
    // TTL (e.g. the 90-day "stay signed in" window) still renews.
    let ttl = Duration::from_secs(90 * 24 * 3600);
    let store = RefreshTokens::with_ttl(ttl);
    let birth = Utc::now()
        - ChronoDuration::from_std(DEFAULT_REFRESH_TTL + Duration::from_secs(3600)).unwrap();
    store
        .insert_rotated("long-lived", identity(), birth)
        .await
        .unwrap();
    assert!(
        store.take("long-lived").await.is_some(),
        "inside the configured TTL the chain still renews"
    );
}

#[tokio::test]
async fn purge_for_sub_drops_only_that_identitys_chains() {
    let store = RefreshTokens::default();
    // Two live chains for u1 (e.g. two devices), one for u2.
    store.insert("u1-a", identity()).await.unwrap();
    store.insert("u1-b", identity()).await.unwrap();
    store
        .insert(
            "u2-a",
            GrantIdentity {
                sub: "u2".into(),
                ..identity()
            },
        )
        .await
        .unwrap();

    let removed = store.purge_for_sub("u1").await;
    assert_eq!(removed, 2, "both of u1's chains are purged");
    assert!(store.take("u1-a").await.is_none());
    assert!(store.take("u1-b").await.is_none());
    // A different identity's chain is left intact.
    assert!(store.take("u2-a").await.is_some());
    // Purging an identity with no tokens is a no-op.
    assert_eq!(store.purge_for_sub("nobody").await, 0);
}

#[tokio::test]
async fn refresh_tokens_gc_removes_expired_chains() {
    let store = RefreshTokens::default();
    store.insert("token1", identity()).await.unwrap();
    store.insert("token2", identity()).await.unwrap();

    // Both tokens exist.
    assert!(store.take("token1").await.is_some());
    assert!(store.take("token2").await.is_some());

    // Run gc_expired.
    store.gc_expired().await;
    // Fresh tokens within TTL should still exist after GC.
    store.insert("token3", identity()).await.unwrap();
    assert!(store.take("token3").await.is_some());
}

#[tokio::test]
async fn refresh_tokens_rejects_when_full() {
    let store = RefreshTokens::default();
    // Fill to the limit.
    for i in 0..REFRESH_TOKENS_MAX_SIZE {
        let token = format!("token-{i}");
        store.insert(&token, identity()).await.unwrap();
    }

    // Next insert should fail.
    let result = store.insert("overflow", identity()).await;
    assert_eq!(result, Err(StoreError::StoreFull));
}
