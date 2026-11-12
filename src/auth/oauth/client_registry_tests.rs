use super::*;

#[tokio::test]
async fn insert_then_lookup_roundtrips() {
    let reg = ClientRegistry::default();
    assert!(reg.insert("c1".into(), vec!["https://app/cb".into()]).await);
    assert_eq!(
        reg.redirect_uris("c1").await,
        Some(vec!["https://app/cb".into()])
    );
    assert_eq!(reg.redirect_uris("unknown").await, None);
}

#[tokio::test]
async fn at_cap_rejects_new_but_updates_existing() {
    let reg = ClientRegistry::default();
    let Backend::Memory(map) = &reg.backend else {
        unreachable!("default() is the memory backend");
    };
    {
        let mut map = map.lock().await;
        for i in 0..CLIENT_CAP {
            map.insert(
                format!("c{i}"),
                RegisteredClient {
                    redirect_uris: vec!["https://app/cb".into()],
                    expires_at: Instant::now() + CLIENT_TTL,
                },
            );
        }
    }
    // At cap: a brand-new client is refused, no live client evicted.
    assert!(
        !reg.insert("overflow".into(), vec!["https://app/cb".into()])
            .await
    );
    assert_eq!(reg.redirect_uris("overflow").await, None);
    assert!(reg.redirect_uris("c0").await.is_some());
    // Updating an already-registered client still succeeds at cap.
    assert!(
        reg.insert("c0".into(), vec!["https://app/new".into()])
            .await
    );
    assert_eq!(
        reg.redirect_uris("c0").await,
        Some(vec!["https://app/new".into()])
    );
}
