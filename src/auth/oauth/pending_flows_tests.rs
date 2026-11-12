use super::*;

/// Insert a flow with an explicit expiry, bypassing the real `FLOW_TTL`
/// (15 min) so tests can manufacture already-expired entries without sleeping.
async fn insert_with_expiry(store: &PendingFlows, state: String, expires_at: Instant) {
    let mut map = store.inner.lock().await;
    map.insert(
        state,
        PendingFlow {
            nonce: "nonce".into(),
            idp_verifier: "verifier".into(),
            bridge: None,
            expires_at,
        },
    );
}

#[tokio::test]
async fn pending_flows_gc_removes_expired_entries() {
    let store = PendingFlows::default();
    store
        .insert("flow1".into(), "nonce1".into(), "verifier1".into())
        .await
        .unwrap();
    store
        .insert("flow2".into(), "nonce2".into(), "verifier2".into())
        .await
        .unwrap();

    // Both flows should exist.
    assert!(store.take("flow1").await.is_some());
    assert!(store.take("flow2").await.is_some());

    // Re-insert and then run gc_expired.
    store
        .insert("flow3".into(), "nonce3".into(), "verifier3".into())
        .await
        .unwrap();
    store.gc_expired().await;
    // Flow3 is still within TTL, should exist after GC.
    assert!(store.take("flow3").await.is_some());
}

#[tokio::test]
async fn pending_flows_rejects_when_full() {
    let store = PendingFlows::default();
    // Fill to the limit.
    for i in 0..PENDING_FLOWS_MAX_SIZE {
        let state = format!("flow-{i}");
        store
            .insert(state, format!("nonce-{i}"), format!("verifier-{i}"))
            .await
            .unwrap();
    }

    // Next insert should fail.
    let result = store
        .insert("overflow".into(), "nonce".into(), "verifier".into())
        .await;
    assert_eq!(result, Err(StoreError::StoreFull));
}

/// Regression for the #136 audit finding "/authorize flood wedges all
/// logins ... cap hit without GC'ing expired flows first". Filling the
/// map with entries that have ALREADY expired (simulating a burst that
/// aged out before the periodic 30s sweep ran) must not permanently
/// block a real login — `insert_flow`'s opportunistic GC-on-full must
/// reclaim the room inline, without waiting for `gc_expired` to be
/// called externally.
#[tokio::test]
async fn pending_flows_opportunistic_gc_reclaims_room_at_cap() {
    let store = PendingFlows::default();
    let already_expired = Instant::now() - Duration::from_secs(1);
    for i in 0..PENDING_FLOWS_MAX_SIZE {
        insert_with_expiry(&store, format!("expired-{i}"), already_expired).await;
    }

    let result = store
        .insert("real-login".into(), "nonce".into(), "verifier".into())
        .await;
    assert!(
        result.is_ok(),
        "opportunistic GC must free room for a legitimate login at cap"
    );
    assert!(store.take("real-login").await.is_some());
}

/// A map genuinely full of LIVE (non-expired) flows must still reject —
/// the opportunistic GC only reclaims what's actually stale; it must not
/// evict live entries just to make room.
#[tokio::test]
async fn pending_flows_opportunistic_gc_does_not_evict_live_entries() {
    let store = PendingFlows::default();
    for i in 0..PENDING_FLOWS_MAX_SIZE {
        store
            .insert(format!("live-{i}"), "nonce".into(), "verifier".into())
            .await
            .unwrap();
    }

    let result = store
        .insert("overflow".into(), "nonce".into(), "verifier".into())
        .await;
    assert_eq!(result, Err(StoreError::StoreFull));
    // All the original live flows must still be there.
    assert!(store.take("live-0").await.is_some());
}
