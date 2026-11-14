use super::*;

fn bridge() -> OAuthBridge {
    OAuthBridge {
        client_id: "mcp-x".into(),
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

#[tokio::test]
async fn consent_is_single_use_and_csrf_is_exact() {
    let store = PendingFlows::default();
    store
        .insert_consent("id".into(), "csrf-token".into(), identity(), bridge())
        .await;
    let consent = store.take_consent("id").await.expect("live");
    assert!(consent.csrf_matches("csrf-token"));
    assert!(!consent.csrf_matches("csrf-toke"));
    assert!(!consent.csrf_matches(""));
    assert!(store.take_consent("id").await.is_none(), "single-use");
}

#[tokio::test]
async fn expired_consent_is_not_returned_and_gc_removes_it() {
    let store = PendingFlows::default();
    store
        .insert_consent("old".into(), "t".into(), identity(), bridge())
        .await;
    if let Some(consent) = store.consents.lock().await.get_mut("old") {
        consent.expires_at = Instant::now() - Duration::from_secs(1);
    }
    assert_eq!(store.gc_expired().await, 1);
    assert!(store.take_consent("old").await.is_none());
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
        store
            .insert_consent(format!("c-{i}"), "t".into(), user, bridge())
            .await;
    }
    // Pin c-0 as soonest-expiring so the victim is not map-order luck.
    if let Some(consent) = store.consents.lock().await.get_mut("c-0") {
        consent.expires_at -= Duration::from_secs(60);
    }
    store
        .insert_consent("new".into(), "t".into(), identity(), bridge())
        .await;
    assert_eq!(store.consents.lock().await.len(), PENDING_CONSENTS_MAX_SIZE);
    assert!(store.take_consent("c-0").await.is_none(), "oldest dropped");
    assert!(store.take_consent("new").await.is_some());
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
    store
        .insert_consent("victim".into(), "t".into(), user("victim"), bridge())
        .await;
    for i in 0..=PENDING_CONSENTS_PER_SUBJECT {
        store
            .insert_consent(format!("loop-{i}"), "t".into(), user("looper"), bridge())
            .await;
        if let Some(consent) = store.consents.lock().await.get_mut(&format!("loop-{i}")) {
            // Strictly increasing expiries so "oldest" is loop-0, not map order.
            consent.expires_at += Duration::from_secs(i as u64);
        }
    }
    let looper_live = store
        .consents
        .lock()
        .await
        .values()
        .filter(|c| c.identity.sub == "looper")
        .count();
    assert_eq!(looper_live, PENDING_CONSENTS_PER_SUBJECT);
    assert!(
        store.take_consent("loop-0").await.is_none(),
        "own oldest evicted"
    );
    assert!(
        store.take_consent("victim").await.is_some(),
        "other user untouched"
    );
}
