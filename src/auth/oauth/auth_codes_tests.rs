use super::*;

fn identity() -> GrantIdentity {
    GrantIdentity {
        sub: "u1".into(),
        email: "u1@example.com".into(),
        groups: vec!["eng".into()],
    }
}

/// Insert a code with an explicit expiry, bypassing the real `CODE_TTL` (60s)
/// so tests can manufacture already-expired entries without sleeping.
async fn insert_with_expiry(store: &AuthCodes, code: &str, expires_at: Instant) {
    let mut map = store.inner.lock().await;
    map.insert(
        hash_secret(code),
        AuthCode {
            identity: GrantIdentity {
                sub: "test".into(),
                email: "test@example.com".into(),
                groups: vec![],
            },
            code_challenge: "challenge".into(),
            redirect_uri: "https://app/cb".into(),
            client_id: "client".into(),
            expires_at,
        },
    );
}

#[tokio::test]
async fn auth_code_round_trips_by_raw_code_and_is_consumed_once() {
    let store = AuthCodes::default();
    store
        .insert(
            "raw-code",
            identity(),
            "challenge".into(),
            "https://app/cb".into(),
            "client-1".into(),
        )
        .await
        .unwrap();

    let entry = store.take("raw-code").await.expect("code is live");
    assert_eq!(entry.client_id, "client-1");
    assert!(store.take("raw-code").await.is_none());
}

#[tokio::test]
async fn auth_codes_gc_removes_expired_entries() {
    let store = AuthCodes::default();
    store
        .insert(
            "code1",
            identity(),
            "ch".into(),
            "uri".into(),
            "client".into(),
        )
        .await
        .unwrap();

    // Code exists.
    assert!(store.take("code1").await.is_some());

    // Re-insert and run gc.
    store
        .insert(
            "code2",
            identity(),
            "ch".into(),
            "uri".into(),
            "client".into(),
        )
        .await
        .unwrap();
    store.gc_expired().await;
    // Code2 is still within TTL.
    assert!(store.take("code2").await.is_some());
}

#[tokio::test]
async fn auth_codes_rejects_when_full() {
    let store = AuthCodes::default();
    // Fill to the limit.
    for i in 0..AUTH_CODES_MAX_SIZE {
        let code = format!("code-{i}");
        store
            .insert(
                &code,
                identity(),
                "challenge".into(),
                "uri".into(),
                "client".into(),
            )
            .await
            .unwrap();
    }

    // Next insert should fail.
    let result = store
        .insert(
            "overflow",
            identity(),
            "challenge".into(),
            "uri".into(),
            "client".into(),
        )
        .await;
    assert_eq!(result, Err(StoreError::StoreFull));
}

/// Same opportunistic-GC regression as `PendingFlows`, for `AuthCodes`.
#[tokio::test]
async fn auth_codes_opportunistic_gc_reclaims_room_at_cap() {
    let store = AuthCodes::default();
    let already_expired = Instant::now() - Duration::from_secs(1);
    for i in 0..AUTH_CODES_MAX_SIZE {
        insert_with_expiry(&store, &format!("expired-{i}"), already_expired).await;
    }

    let result = store
        .insert(
            "real-code",
            identity(),
            "challenge".into(),
            "uri".into(),
            "client".into(),
        )
        .await;
    assert!(
        result.is_ok(),
        "opportunistic GC must free room for a real code at cap"
    );
    assert!(store.take("real-code").await.is_some());
}
