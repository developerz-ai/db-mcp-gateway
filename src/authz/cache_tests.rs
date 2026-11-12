//! Unit tests for the cache's single flight, per-subject revision and sweep,
//! against a counting in-memory repo.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio::sync::Notify;
use uuid::Uuid;

use super::*;
use crate::auth::SessionId;
use crate::state::permissions::{
    GrantAction, LiveGrant, Page, PermissionsDatabase, PermissionsGrant, PermissionsUser, RepoError,
};

#[derive(Debug, Default)]
struct CountingRepo {
    loads: AtomicUsize,
    /// When set, every load parks until notified — lets a test interleave.
    gate: Option<Arc<Notify>>,
}

#[async_trait]
impl PermissionsRepo for CountingRepo {
    async fn get_user(&self, _: Uuid) -> Result<Option<PermissionsUser>, RepoError> {
        Ok(None)
    }
    async fn list_users(&self, _: Page) -> Result<Vec<PermissionsUser>, RepoError> {
        Ok(Vec::new())
    }
    async fn get_database(&self, _: Uuid) -> Result<Option<PermissionsDatabase>, RepoError> {
        Ok(None)
    }
    async fn list_databases(&self, _: Page) -> Result<Vec<PermissionsDatabase>, RepoError> {
        Ok(Vec::new())
    }
    async fn get_grant(&self, _: Uuid) -> Result<Option<PermissionsGrant>, RepoError> {
        Ok(None)
    }
    async fn list_grants(
        &self,
        _: Option<Uuid>,
        _: Option<Uuid>,
        _: Page,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        Ok(Vec::new())
    }
    async fn live_grants_for_sub(&self, _: &str) -> Result<Vec<LiveGrant>, RepoError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        Ok(vec![LiveGrant {
            id: Uuid::nil(),
            server: "prod".into(),
            db_name: None,
            action: GrantAction::QueryRead,
            constraints: serde_json::json!({}),
        }])
    }
}

fn identity(sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: sub.to_string(),
        user_email: "u@example.com".into(),
        groups: Vec::new(),
        issued_at: chrono::Utc::now(),
        kind: crate::auth::IdentityKind::Sso,
    }
}

fn cache_over(repo: &Arc<CountingRepo>, ttl: Duration) -> PermissionsCache {
    PermissionsCache::new(repo.clone(), ttl)
}

#[tokio::test]
async fn hit_skips_the_store_and_invalidation_reloads() {
    let repo = Arc::new(CountingRepo::default());
    let cache = cache_over(&repo, Duration::from_secs(60));
    let alice = identity("alice");

    cache.get_for(&alice).await.unwrap();
    cache.get_for(&alice).await.unwrap();
    assert_eq!(repo.loads.load(Ordering::SeqCst), 1);

    cache.apply(&PermissionsChange::User("bob".into())).await;
    cache.get_for(&alice).await.unwrap();
    assert_eq!(
        repo.loads.load(Ordering::SeqCst),
        1,
        "other subject untouched"
    );

    cache.apply(&PermissionsChange::User("alice".into())).await;
    cache.get_for(&alice).await.unwrap();
    assert_eq!(repo.loads.load(Ordering::SeqCst), 2);

    cache.apply(&PermissionsChange::All).await;
    cache.get_for(&alice).await.unwrap();
    assert_eq!(repo.loads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn concurrent_misses_share_one_load() {
    let gate = Arc::new(Notify::new());
    let repo = Arc::new(CountingRepo {
        gate: Some(gate.clone()),
        ..CountingRepo::default()
    });
    let cache = cache_over(&repo, Duration::from_secs(60));
    let waiters: Vec<_> = (0..8)
        .map(|_| {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get_for(&identity("alice")).await })
        })
        .collect();
    while repo.loads.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    gate.notify_one();
    for w in waiters {
        assert_eq!(w.await.unwrap().unwrap().len(), 1);
    }
    assert_eq!(repo.loads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn load_overtaken_by_invalidation_is_not_cached() {
    let gate = Arc::new(Notify::new());
    let repo = Arc::new(CountingRepo {
        gate: Some(gate.clone()),
        ..CountingRepo::default()
    });
    let cache = cache_over(&repo, Duration::from_secs(60));
    let loader = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.get_for(&identity("alice")).await })
    };
    while repo.loads.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    // The revoke commits while the first load is in flight.
    cache.apply(&PermissionsChange::User("alice".into())).await;
    gate.notify_one();
    // The retry loads again; release it too.
    while repo.loads.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    gate.notify_one();
    loader.await.unwrap().unwrap();
    assert_eq!(repo.loads.load(Ordering::SeqCst), 2, "stale load retried");
    assert!(cache.fresh("alice").await.is_some(), "retry was cached");
}

#[tokio::test]
async fn service_identity_never_reads_the_store() {
    let repo = Arc::new(CountingRepo::default());
    let cache = cache_over(&repo, Duration::from_secs(60));
    let service = Identity {
        kind: crate::auth::IdentityKind::Service,
        ..identity("service:ci-bot")
    };
    let grants = cache.get_for(&service).await.unwrap();
    assert!(grants.is_empty());
    assert_eq!(repo.loads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn insert_sweeps_expired_idle_slots() {
    let repo = Arc::new(CountingRepo::default());
    let cache = cache_over(&repo, Duration::from_millis(1));
    cache.get_for(&identity("a")).await.unwrap();
    cache.get_for(&identity("b")).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while cache.fresh("a").await.is_some() {
        assert!(Instant::now() < deadline, "entry never expired");
        tokio::task::yield_now().await;
    }
    cache.get_for(&identity("c")).await.unwrap();
    assert!(cache.slot_count().await <= 2, "expired slots swept");
}
