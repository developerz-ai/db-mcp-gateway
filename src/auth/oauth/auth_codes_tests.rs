use super::*;

fn identity() -> GrantIdentity {
    GrantIdentity {
        sub: "u1".into(),
        email: "u1@example.com".into(),
        groups: vec!["eng".into()],
    }
}

async fn insert(store: &AuthCodes, code: &str) -> Result<(), StoreError> {
    store
        .insert(
            code,
            identity(),
            "challenge".into(),
            "https://app/cb".into(),
            "client-1".into(),
        )
        .await
}

async fn take(store: &AuthCodes, code: &str) -> Option<AuthCode> {
    store.take(code).await.expect("memory take")
}

/// Insert a code with an explicit expiry, bypassing the real `CODE_TTL` (60s)
/// so tests can manufacture already-expired entries without sleeping.
async fn insert_with_expiry(store: &AuthCodes, code: &str, expires_at: DateTime<Utc>) {
    let Backend::Memory(map) = &store.backend else {
        panic!("memory backend");
    };
    map.lock().await.insert(
        hash_secret(code),
        AuthCode {
            identity: identity(),
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
    insert(&store, "raw-code").await.unwrap();

    let entry = take(&store, "raw-code").await.expect("code is live");
    assert_eq!(entry.client_id, "client-1");
    assert!(take(&store, "raw-code").await.is_none());
}

#[tokio::test]
async fn restored_code_is_redeemable_again() {
    let store = AuthCodes::default();
    insert(&store, "raw-code").await.unwrap();
    let entry = take(&store, "raw-code").await.expect("code is live");
    store.restore("raw-code", entry).await.unwrap();
    assert!(take(&store, "raw-code").await.is_some());
}

#[tokio::test]
async fn auth_codes_gc_removes_only_expired_entries() {
    let store = AuthCodes::default();
    insert_with_expiry(&store, "stale", Utc::now() - Duration::seconds(1)).await;
    insert(&store, "live").await.unwrap();
    assert_eq!(store.gc_expired().await, 1);
    assert!(take(&store, "stale").await.is_none());
    assert!(take(&store, "live").await.is_some());
}

#[tokio::test]
async fn expired_code_is_not_returned() {
    let store = AuthCodes::default();
    insert_with_expiry(&store, "stale", Utc::now() - Duration::seconds(1)).await;
    assert!(take(&store, "stale").await.is_none());
}

#[tokio::test]
async fn auth_codes_rejects_when_full() {
    let store = AuthCodes::default();
    for i in 0..AUTH_CODES_MAX_SIZE {
        insert(&store, &format!("code-{i}")).await.unwrap();
    }
    assert_eq!(insert(&store, "overflow").await, Err(StoreError::StoreFull));
}

/// A burst of codes that has since expired must not wedge new logins until
/// the periodic sweep.
#[tokio::test]
async fn auth_codes_opportunistic_gc_reclaims_room_at_cap() {
    let store = AuthCodes::default();
    let already_expired = Utc::now() - Duration::seconds(1);
    for i in 0..AUTH_CODES_MAX_SIZE {
        insert_with_expiry(&store, &format!("expired-{i}"), already_expired).await;
    }

    assert!(
        insert(&store, "real-code").await.is_ok(),
        "opportunistic GC must free room for a real code at cap"
    );
    assert!(take(&store, "real-code").await.is_some());
}
