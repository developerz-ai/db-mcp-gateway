use super::*;
use chrono::Duration as ChronoDuration;

fn identity() -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: "sub".into(),
        user_email: "e@example.com".into(),
        groups: vec!["g".into()],
        issued_at: Utc::now(),
        kind: crate::auth::IdentityKind::Sso,
    }
}

fn expires_in(secs: i64) -> DateTime<Utc> {
    Utc::now() + ChronoDuration::seconds(secs)
}

fn cache(ttl_secs: u64, max_entries: usize) -> SessionCache {
    SessionCache::new(SessionCacheConfig {
        ttl: Duration::from_secs(ttl_secs),
        max_entries,
    })
}

#[tokio::test]
async fn fresh_active_session_is_returned() {
    let cache = cache(3600, 16);
    let id = identity();
    let sid = id.session_id;
    cache.insert(id, expires_in(3600)).await;
    assert!(matches!(cache.get(sid, Utc::now()).await, Cached::Live(_)));
}

#[tokio::test]
async fn absent_session_is_a_miss() {
    let cache = cache(3600, 16);
    assert!(matches!(
        cache.get(SessionId::new(), Utc::now()).await,
        Cached::Miss
    ));
}

#[tokio::test]
async fn stale_entry_forces_revalidation() {
    // ttl = 0 → every entry is instantly stale: the cross-replica revocation
    // safety net at its extreme.
    let cache = cache(0, 16);
    let id = identity();
    let sid = id.session_id;
    cache.insert(id, expires_in(3600)).await;
    assert!(matches!(cache.get(sid, Utc::now()).await, Cached::Miss));
}

#[tokio::test]
async fn expired_session_is_gone() {
    let cache = cache(3600, 16);
    let id = identity();
    let sid = id.session_id;
    cache.insert(id, expires_in(-1)).await;
    assert!(matches!(
        cache.get(sid, Utc::now()).await,
        Cached::Gone(Inactive::Expired)
    ));
}

#[tokio::test]
async fn tombstone_rejects_without_db() {
    let cache = cache(3600, 16);
    let sid = SessionId::new();
    cache.tombstone(sid, Inactive::Revoked).await;
    assert!(matches!(
        cache.get(sid, Utc::now()).await,
        Cached::Gone(Inactive::Revoked)
    ));
}

/// The revoke/lookup race: a lookup that read the row before the revoke
/// committed must not re-cache the session over the tombstone.
#[tokio::test]
async fn tombstone_beats_a_racing_insert() {
    let cache = cache(3600, 16);
    let id = identity();
    let sid = id.session_id;
    cache.tombstone(sid, Inactive::Revoked).await;
    cache.insert(id, expires_in(3600)).await;
    assert!(matches!(
        cache.get(sid, Utc::now()).await,
        Cached::Gone(Inactive::Revoked)
    ));
}

/// Even with no freshness TTL the tombstone outlives an in-flight DB read.
#[tokio::test]
async fn tombstone_survives_zero_ttl() {
    let cache = cache(0, 16);
    let id = identity();
    let sid = id.session_id;
    cache.tombstone(sid, Inactive::Revoked).await;
    cache.insert(id, expires_in(3600)).await;
    assert!(matches!(
        cache.get(sid, Utc::now()).await,
        Cached::Gone(Inactive::Revoked)
    ));
}

#[tokio::test]
async fn full_cache_serves_uncached_instead_of_scanning() {
    let cache = cache(3600, 2);
    let (a, b, c) = (identity(), identity(), identity());
    let (sa, sc) = (a.session_id, c.session_id);
    cache.insert(a, expires_in(3600)).await;
    cache.insert(b, expires_in(3600)).await;
    cache.insert(c, expires_in(3600)).await;

    assert_eq!(cache.len().await, 2, "size cap is hard");
    assert!(matches!(cache.get(sa, Utc::now()).await, Cached::Live(_)));
    assert!(matches!(cache.get(sc, Utc::now()).await, Cached::Miss));
}

#[tokio::test]
async fn tombstone_is_admitted_at_capacity() {
    let cache = cache(3600, 1);
    cache.insert(identity(), expires_in(3600)).await;
    let sid = SessionId::new();
    cache.tombstone(sid, Inactive::Revoked).await;
    assert!(matches!(
        cache.get(sid, Utc::now()).await,
        Cached::Gone(Inactive::Revoked)
    ));
}

#[tokio::test]
async fn sweep_drops_stale_entries_and_keeps_tombstones() {
    let cache = cache(0, 16);
    cache.insert(identity(), expires_in(3600)).await;
    let sid = SessionId::new();
    cache.tombstone(sid, Inactive::Revoked).await;
    cache.sweep().await;
    assert_eq!(
        cache.len().await,
        1,
        "stale live entry swept, tombstone kept"
    );
    assert!(matches!(
        cache.get(sid, Utc::now()).await,
        Cached::Gone(Inactive::Revoked)
    ));
}

#[tokio::test]
async fn zero_capacity_is_clamped_to_one() {
    let cache = cache(3600, 0);
    cache.insert(identity(), expires_in(3600)).await;
    assert_eq!(cache.len().await, 1);
}

#[tokio::test]
async fn concurrent_flights_share_one_lock() {
    let cache = cache(3600, 16);
    let sid = SessionId::new();
    let a = cache.flight(sid).await;
    let b = cache.flight(sid).await;
    assert!(Arc::ptr_eq(&a, &b));
    cache.end_flight(sid).await;
    let c = cache.flight(sid).await;
    assert!(!Arc::ptr_eq(&a, &c), "a finished flight is forgotten");
}
