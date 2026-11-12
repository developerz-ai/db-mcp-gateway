use super::*;

async fn insert(store: &PendingFlows, state: &str) {
    store
        .insert(state.into(), "nonce".into(), "verifier".into())
        .await;
}

/// Insert a flow with an explicit expiry, bypassing the real `FLOW_TTL`
/// (15 min) so tests can manufacture already-expired entries without sleeping.
async fn insert_with_expiry(store: &PendingFlows, state: String, expires_at: Instant) {
    let mut flows = store.inner.lock().await;
    flows.order.push_back(state.clone());
    flows.by_state.insert(
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
async fn take_is_one_time() {
    let store = PendingFlows::default();
    insert(&store, "flow1").await;
    assert!(store.take("flow1").await.is_some());
    assert!(store.take("flow1").await.is_none());
}

#[tokio::test]
async fn expired_flow_is_not_returned_and_gc_removes_it() {
    let store = PendingFlows::default();
    insert_with_expiry(
        &store,
        "stale".into(),
        Instant::now() - Duration::from_secs(1),
    )
    .await;
    insert(&store, "live").await;
    store.gc_expired().await;
    {
        let flows = store.inner.lock().await;
        assert_eq!(flows.by_state.len(), 1);
        assert_eq!(flows.order.len(), 1, "order compacted with the map");
    }
    assert!(store.take("stale").await.is_none());
    assert!(store.take("live").await.is_some());
}

/// `/authorize` is unauthenticated: a flood that fills the map must not block
/// a real login. The oldest flow is evicted instead of refusing the new one.
#[tokio::test]
async fn at_cap_evicts_the_oldest_flow() {
    let store = PendingFlows::default();
    for i in 0..PENDING_FLOWS_MAX_SIZE {
        insert(&store, &format!("flood-{i}")).await;
    }
    insert(&store, "real-login").await;

    assert_eq!(
        store.inner.lock().await.by_state.len(),
        PENDING_FLOWS_MAX_SIZE
    );
    assert!(store.take("flood-0").await.is_none(), "oldest evicted");
    assert!(store.take("flood-1").await.is_some());
    assert!(store.take("real-login").await.is_some());
}

/// Eviction skips states already taken (still queued in the order log).
#[tokio::test]
async fn eviction_skips_taken_flows() {
    let store = PendingFlows::default();
    for i in 0..PENDING_FLOWS_MAX_SIZE {
        insert(&store, &format!("f-{i}")).await;
    }
    assert!(store.take("f-0").await.is_some());
    insert(&store, "a").await; // room freed by the take: no eviction
    insert(&store, "b").await; // at cap: evicts f-1, skipping taken f-0
    assert!(store.take("f-1").await.is_none());
    assert!(store.take("f-2").await.is_some());
    assert!(store.take("a").await.is_some() && store.take("b").await.is_some());
}
