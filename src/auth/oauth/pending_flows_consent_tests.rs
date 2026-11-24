use std::collections::HashMap;

use super::super::pending_flows_mem::HeldConsent;
use super::*;

fn bridge() -> OAuthBridge {
    OAuthBridge {
        client_id: "mcp-x".into(),
        client_name: None,
        client_redirect_uri: "https://app.example.com/cb".into(),
        client_state: "s".into(),
        code_challenge: "c".into(),
        resource: None,
    }
}

fn identity() -> GrantIdentity {
    GrantIdentity {
        sub: "sub".into(),
        email: "u@example.com".into(),
        groups: vec![],
    }
}

async fn insert(store: &PendingFlows, id: &str, identity: GrantIdentity) {
    store
        .insert_consent(id, "t", identity, bridge())
        .await
        .expect("memory insert");
}

async fn take(store: &PendingFlows, id: &str) -> Option<PendingConsent> {
    store.take_consent(id).await.expect("memory take")
}

async fn consents(
    store: &PendingFlows,
) -> tokio::sync::MutexGuard<'_, HashMap<[u8; 32], HeldConsent>> {
    store
        .memory()
        .expect("memory backend")
        .consents
        .lock()
        .await
}

async fn shift_expiry(store: &PendingFlows, id: &str, by: Duration) {
    if let Some(held) = consents(store).await.get_mut(&hash_secret(id)) {
        held.expires_at += by;
    }
}

#[tokio::test]
async fn consent_is_single_use_and_csrf_is_exact() {
    let store = PendingFlows::default();
    store
        .insert_consent("id", "csrf-token", identity(), bridge())
        .await
        .expect("memory insert");
    let consent = take(&store, "id").await.expect("live");
    assert!(consent.csrf_matches("csrf-token"));
    assert!(!consent.csrf_matches("csrf-toke"));
    assert!(!consent.csrf_matches(""));
    assert!(take(&store, "id").await.is_none(), "single-use");
}

#[tokio::test]
async fn expired_consent_is_not_returned_and_gc_removes_it() {
    let store = PendingFlows::default();
    insert(&store, "old", identity()).await;
    shift_expiry(&store, "old", -Duration::minutes(11)).await;
    assert_eq!(store.gc_expired().await, 1);
    assert!(take(&store, "old").await.is_none());
}

#[tokio::test]
async fn at_cap_drops_the_soonest_expiring_consent() {
    let store = PendingFlows::default();
    // Distinct subjects, so only the global cap is in play.
    for i in 0..PENDING_CONSENTS_MAX_SIZE {
        let user = GrantIdentity {
            sub: format!("user-{i}"),
            ..identity()
        };
        insert(&store, &format!("c-{i}"), user).await;
    }
    // Pin c-0 as soonest-expiring so the victim is not map-order luck.
    shift_expiry(&store, "c-0", -Duration::seconds(60)).await;
    insert(&store, "new", identity()).await;
    assert_eq!(consents(&store).await.len(), PENDING_CONSENTS_MAX_SIZE);
    assert!(take(&store, "c-0").await.is_none(), "oldest dropped");
    assert!(take(&store, "new").await.is_some());
}

/// One account looping silent SSO logins must only ever displace its own
/// pending consents, never another user's.
#[tokio::test]
async fn per_subject_cap_evicts_only_that_subjects_oldest() {
    let store = PendingFlows::default();
    let user = |sub: &str| GrantIdentity {
        sub: sub.into(),
        ..identity()
    };
    insert(&store, "victim", user("victim")).await;
    for i in 0..=PENDING_CONSENTS_PER_SUBJECT {
        let id = format!("loop-{i}");
        insert(&store, &id, user("looper")).await;
        // Strictly increasing expiries so "oldest" is loop-0, not map order.
        shift_expiry(&store, &id, Duration::seconds(i as i64)).await;
    }
    let looper_live = consents(&store)
        .await
        .values()
        .filter(|held| held.consent.identity.sub == "looper")
        .count();
    assert_eq!(looper_live, PENDING_CONSENTS_PER_SUBJECT);
    assert!(take(&store, "loop-0").await.is_none(), "own oldest evicted");
    assert!(
        take(&store, "victim").await.is_some(),
        "other user untouched"
    );
}
