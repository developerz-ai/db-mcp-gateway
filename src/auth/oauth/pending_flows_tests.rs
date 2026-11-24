use chrono::{DateTime, Utc};

use super::super::pending_flows_mem::{Flows, HeldFlow};
use super::*;

async fn insert(store: &PendingFlows, state: &str) {
    store.insert(state).await.expect("memory insert");
}

async fn take(store: &PendingFlows, state: &str) -> Option<PendingFlow> {
    store.take(state).await.expect("memory take")
}

async fn flows(store: &PendingFlows) -> tokio::sync::MutexGuard<'_, Flows> {
    store.memory().expect("memory backend").flows.lock().await
}

/// Insert a flow with an explicit expiry, bypassing the real `FLOW_TTL`
/// (15 min) so tests can manufacture already-expired entries without sleeping.
async fn insert_with_expiry(store: &PendingFlows, state: &str, expires_at: DateTime<Utc>) {
    let state_hash = hash_secret(state);
    let mut flows = flows(store).await;
    flows.order.push_back(state_hash);
    flows.by_state.insert(
        state_hash,
        HeldFlow {
            bridge: None,
            expires_at,
        },
    );
}

#[tokio::test]
async fn take_is_one_time() {
    let store = PendingFlows::default();
    insert(&store, "flow1").await;
    assert!(take(&store, "flow1").await.is_some());
    assert!(take(&store, "flow1").await.is_none());
}

/// The callback gets back exactly the secrets the login sent the IdP.
#[tokio::test]
async fn taken_flow_carries_the_secrets_sent_to_the_idp() {
    let store = PendingFlows::default();
    let sent = store.login_secrets("flow1");
    insert(&store, "flow1").await;
    let flow = take(&store, "flow1").await.expect("live");
    assert_eq!(flow.nonce, sent.nonce);
    assert_eq!(flow.idp_verifier, sent.idp_verifier);
    assert!(crate::auth::pkce::verify(
        &flow.idp_verifier,
        &sent.idp_challenge()
    ));
}

#[tokio::test]
async fn expired_flow_is_not_returned_and_gc_removes_it() {
    let store = PendingFlows::default();
    insert_with_expiry(&store, "stale", Utc::now() - Duration::seconds(1)).await;
    insert(&store, "live").await;
    store.gc_expired().await;
    {
        let flows = flows(&store).await;
        assert_eq!(flows.by_state.len(), 1);
        assert_eq!(flows.order.len(), 1, "order compacted with the map");
    }
    assert!(take(&store, "stale").await.is_none());
    assert!(take(&store, "live").await.is_some());
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

    assert_eq!(flows(&store).await.by_state.len(), PENDING_FLOWS_MAX_SIZE);
    assert!(take(&store, "flood-0").await.is_none(), "oldest evicted");
    assert!(take(&store, "flood-1").await.is_some());
    assert!(take(&store, "real-login").await.is_some());
}

/// Eviction skips states already taken (still queued in the order log).
#[tokio::test]
async fn eviction_skips_taken_flows() {
    let store = PendingFlows::default();
    for i in 0..PENDING_FLOWS_MAX_SIZE {
        insert(&store, &format!("f-{i}")).await;
    }
    assert!(take(&store, "f-0").await.is_some());
    insert(&store, "a").await; // room freed by the take: no eviction
    insert(&store, "b").await; // at cap: evicts f-1, skipping taken f-0
    assert!(take(&store, "f-1").await.is_none());
    assert!(take(&store, "f-2").await.is_some());
    assert!(take(&store, "a").await.is_some() && take(&store, "b").await.is_some());
}
