use super::*;

const URI: &str = "https://app/cb";

async fn fill(reg: &ClientRegistry, authorised: bool) {
    let Backend::Memory(map) = &reg.backend else {
        unreachable!("default() is the memory backend");
    };
    let mut map = map.lock().await;
    for i in 0..CLIENT_CAP {
        // Distinct, ordered, all within the last 17 minutes.
        let created_at = Utc::now() - ChronoDuration::milliseconds((CLIENT_CAP - i) * 100);
        let ttl = if authorised {
            CLIENT_TTL
        } else {
            UNAUTHORISED_CLIENT_TTL
        };
        map.insert(
            format!("c{i}"),
            RegisteredClient {
                redirect_uris: vec![URI.into()],
                created_at,
                expires_at: created_at + ttl,
            },
        );
    }
}

#[tokio::test]
async fn insert_then_lookup_roundtrips() {
    let reg = ClientRegistry::default();
    reg.insert("c1".into(), vec![URI.into()]).await.unwrap();
    assert_eq!(reg.redirect_uris("c1").await, Some(vec![URI.into()]));
    assert_eq!(reg.redirect_uris("unknown").await, None);
}

#[tokio::test]
async fn first_authorize_promotes_the_client_to_the_long_ttl() {
    let reg = ClientRegistry::default();
    reg.insert("c1".into(), vec![URI.into()]).await.unwrap();
    let Backend::Memory(map) = &reg.backend else {
        unreachable!();
    };
    assert!(
        map.lock().await["c1"].evictable(Utc::now()),
        "unused: evictable"
    );
    reg.redirect_uris("c1").await.expect("live");
    assert!(!map.lock().await["c1"].evictable(Utc::now()), "used: kept");
}

#[tokio::test]
async fn at_cap_evicts_the_oldest_never_authorised_client() {
    let reg = ClientRegistry::default();
    fill(&reg, false).await;
    reg.insert("newcomer".into(), vec![URI.into()])
        .await
        .expect("room made by eviction");
    assert_eq!(reg.redirect_uris("c0").await, None, "oldest unused evicted");
    assert!(reg.redirect_uris("c1").await.is_some());
    assert!(reg.redirect_uris("newcomer").await.is_some());
}

#[tokio::test]
async fn full_of_authorised_clients_is_store_full() {
    let reg = ClientRegistry::default();
    fill(&reg, true).await;
    assert_eq!(
        reg.insert("overflow".into(), vec![URI.into()]).await,
        Err(StoreError::StoreFull)
    );
    assert!(
        reg.redirect_uris("c0").await.is_some(),
        "no live client evicted"
    );
}

#[tokio::test]
async fn gc_drops_only_expired_clients() {
    let reg = ClientRegistry::default();
    reg.insert("live".into(), vec![URI.into()]).await.unwrap();
    let Backend::Memory(map) = &reg.backend else {
        unreachable!();
    };
    map.lock().await.insert(
        "stale".into(),
        RegisteredClient {
            redirect_uris: vec![URI.into()],
            created_at: Utc::now() - ChronoDuration::hours(3),
            expires_at: Utc::now() - ChronoDuration::hours(2),
        },
    );
    reg.gc_expired().await;
    let map = map.lock().await;
    assert!(map.contains_key("live") && !map.contains_key("stale"));
}

#[tokio::test]
async fn adopted_client_is_authorised_immediately() {
    let reg = ClientRegistry::default();
    reg.adopt("adopted".into(), URI.into()).await.unwrap();
    let Backend::Memory(map) = &reg.backend else {
        unreachable!();
    };
    assert!(!map.lock().await["adopted"].evictable(Utc::now()));
}
