//! `SessionStore`: the state DB fronted by an in-memory cache so revocation is
//! honored — a revoke sets `revoked_at` and tombstones the cache entry; lookup
//! checks both. See [`session_cache`](super::session_cache) for the
//! cross-replica staleness bound.
//!
//! The `*_in` methods run against a caller's transaction (OAuth rotation, the
//! admin revoke-sessions endpoint); the caller reports the outcome with
//! [`SessionStore::committed`] once the transaction commits, never before — a
//! rolled-back revoke must not tombstone a still-valid session.

use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::errors::AuthError;
use super::session::{Identity, Session, SessionId};
use super::session_cache::{Cached, Inactive, SessionCache, SessionCacheConfig};
use crate::state::sessions::{self, NewSession};

/// How long an expired row outlives its `expires_at` before GC deletes it.
/// Longer than the session JWT's verification leeway, so a JWT that still
/// verifies always finds its row (and its `revoked_at`).
const GC_GRACE: ChronoDuration = ChronoDuration::hours(1);

/// Cache + DB. Cheap to clone — internal `Arc` shares the same cache and pool.
#[derive(Clone)]
pub struct SessionStore {
    pool: PgPool,
    cache: Arc<SessionCache>,
}

impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `PgPool` Debug leaks the DSN.
        f.debug_struct("SessionStore")
            .field("pool", &"<PgPool>")
            .finish_non_exhaustive()
    }
}

impl SessionStore {
    /// Store with default cache tuning; production overrides via
    /// [`Self::with_cache_config`] (TTL from `SESSION_CACHE_TTL_SECONDS`).
    pub fn new(pool: PgPool) -> Self {
        Self::with_cache_config(pool, SessionCacheConfig::default())
    }

    /// Store with explicit cache tuning.
    pub fn with_cache_config(pool: PgPool, config: SessionCacheConfig) -> Self {
        Self {
            pool,
            cache: Arc::new(SessionCache::new(config)),
        }
    }

    /// The state-DB pool, for callers that open a transaction around `*_in`.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Persist a new session row and warm the cache.
    ///
    /// `original_issued_at`: when `Some`, overrides the row's `issued_at` with
    /// the caller's value instead of stamping `now()`. Used by the OAuth
    /// refresh path to carry the original `/authorize` login time across token
    /// rotations so `admin.session_max_age_secs` counts from the first login,
    /// not from the latest refresh. Pass `None` for all fresh sessions.
    pub async fn create(
        &self,
        user_sub: &str,
        user_email: &str,
        groups: &[String],
        ttl: std::time::Duration,
        agent_client: Option<&str>,
        original_issued_at: Option<DateTime<Utc>>,
    ) -> Result<Session, AuthError> {
        let session = Session {
            agent_client: agent_client.map(str::to_string),
            ..Self::prepare(user_sub, user_email, groups, ttl, original_issued_at)
        };
        let mut conn = self.pool.acquire().await?;
        Self::insert_in(&mut conn, &session).await?;
        self.committed(Some(&session), &[]).await;
        Ok(session)
    }

    /// Build a session that [`Self::insert_in`] will persist. An out-of-range
    /// `ttl` yields `expires_at == issued_at`, which the table's CHECK rejects:
    /// fail closed, never a silent default lifetime. `AuthConfig::from_env`
    /// bounds the configured TTLs, so production never reaches that path.
    pub fn prepare(
        user_sub: &str,
        user_email: &str,
        groups: &[String],
        ttl: std::time::Duration,
        original_issued_at: Option<DateTime<Utc>>,
    ) -> Session {
        let now = Utc::now();
        let expires_at = ChronoDuration::from_std(ttl)
            .ok()
            .and_then(|ttl| now.checked_add_signed(ttl))
            .unwrap_or(now);
        Session {
            id: SessionId::new(),
            user_sub: user_sub.to_string(),
            user_email: user_email.to_string(),
            groups: groups.to_vec(),
            agent_client: None,
            issued_at: original_issued_at.unwrap_or(now),
            expires_at,
            revoked_at: None,
        }
    }

    pub async fn insert_in(conn: &mut PgConnection, session: &Session) -> Result<(), AuthError> {
        sessions::insert(
            conn,
            &NewSession {
                id: Uuid::from(session.id),
                user_sub: &session.user_sub,
                user_email: &session.user_email,
                groups: &session.groups,
                agent_client: session.agent_client.as_deref(),
                issued_at: session.issued_at,
                expires_at: session.expires_at,
            },
        )
        .await?;
        Ok(())
    }

    /// Resolve a session id to an Identity. `RevokedSession` if the row is
    /// revoked or expired, `InvalidSession` if missing. Concurrent misses for
    /// one id share a single DB read.
    pub async fn lookup(&self, id: SessionId) -> Result<Identity, AuthError> {
        if let Some(result) = self.cached(id).await {
            return result;
        }
        let flight = self.cache.flight(id).await;
        let result = {
            let _leader = flight.lock().await;
            // A previous holder of this flight may have just filled the cache.
            match self.cached(id).await {
                Some(result) => result,
                None => self.load(id).await,
            }
        };
        self.cache.end_flight(id).await;
        result
    }

    async fn cached(&self, id: SessionId) -> Option<Result<Identity, AuthError>> {
        match self.cache.get(id, Utc::now()).await {
            Cached::Live(identity) => Some(Ok(Identity::clone(&identity))),
            Cached::Gone(reason) => Some(Err(reason.into())),
            Cached::Miss => None,
        }
    }

    async fn load(&self, id: SessionId) -> Result<Identity, AuthError> {
        let Some(row) = sessions::fetch(&self.pool, Uuid::from(id)).await? else {
            self.cache.tombstone(id, Inactive::Unknown).await;
            return Err(Inactive::Unknown.into());
        };
        let session = Session::from(row);
        if let Some(reason) = session.inactive(Utc::now()) {
            self.cache.tombstone(id, reason).await;
            return Err(reason.into());
        }
        let identity = session.identity();
        self.cache
            .insert(identity.clone(), session.expires_at)
            .await;
        Ok(identity)
    }

    /// Mark a session revoked in the DB and tombstone it in cache. Idempotent.
    pub async fn revoke(&self, id: SessionId) -> Result<(), AuthError> {
        let mut conn = self.pool.acquire().await?;
        let revoked = Self::revoke_in(&mut conn, id).await?;
        self.cache.tombstone(id, Inactive::Revoked).await;
        if revoked {
            metrics::counter!("sessions_revoked_total").increment(1);
        }
        Ok(())
    }

    /// Revoke `id` inside the caller's transaction. `false` when the session
    /// was unknown or already revoked.
    pub async fn revoke_in(conn: &mut PgConnection, id: SessionId) -> Result<bool, AuthError> {
        Ok(sessions::revoke(conn, Uuid::from(id)).await? > 0)
    }

    /// Revoke every live session of `user_sub` (logout everywhere). Returns how
    /// many were revoked.
    pub async fn revoke_all_for_sub(&self, user_sub: &str) -> Result<usize, AuthError> {
        let mut conn = self.pool.acquire().await?;
        let ids = Self::revoke_all_for_sub_in(&mut conn, user_sub).await?;
        self.committed(None, &ids).await;
        Ok(ids.len())
    }

    /// Revoke every live session of `user_sub` inside the caller's transaction.
    pub async fn revoke_all_for_sub_in(
        conn: &mut PgConnection,
        user_sub: &str,
    ) -> Result<Vec<SessionId>, AuthError> {
        let ids = sessions::revoke_all_for_sub(conn, user_sub).await?;
        Ok(ids.into_iter().map(SessionId::from).collect())
    }

    /// Apply a committed transaction's outcome to the cache and counters:
    /// warm `created`, tombstone `revoked`.
    pub async fn committed(&self, created: Option<&Session>, revoked: &[SessionId]) {
        for &id in revoked {
            self.cache.tombstone(id, Inactive::Revoked).await;
        }
        if !revoked.is_empty() {
            metrics::counter!("sessions_revoked_total").increment(revoked.len() as u64);
        }
        if let Some(session) = created {
            self.cache
                .insert(session.identity(), session.expires_at)
                .await;
            metrics::counter!("sessions_created_total").increment(1);
        }
    }

    /// Delete rows expired for longer than the GC grace and sweep stale cache
    /// entries. Idempotent, so concurrent replicas can run it. Returns rows
    /// deleted.
    pub async fn gc_expired(&self) -> Result<u64, AuthError> {
        self.cache.sweep().await;
        Ok(sessions::delete_expired(&self.pool, GC_GRACE).await?)
    }
}

impl From<Inactive> for AuthError {
    fn from(reason: Inactive) -> Self {
        match reason {
            Inactive::Revoked => AuthError::RevokedSession,
            Inactive::Expired => AuthError::ExpiredSession,
            Inactive::Unknown => AuthError::InvalidSession,
        }
    }
}
