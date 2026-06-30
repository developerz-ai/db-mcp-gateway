//! Sessions: the authoritative identity for an authenticated request.
//!
//! `SessionStore` fronts the state DB with an in-memory cache so revocation is
//! honored: logout sets `revoked_at` and evicts the cache; lookup checks both.
//! The cache is bounded with a freshness TTL — see
//! [`session_cache`](super::session_cache) for the cross-replica staleness bound.

use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::errors::AuthError;
use super::session_cache::{SessionCache, SessionCacheConfig};

/// Newtype over the session row UUID. Construct via `new()` or `from(Uuid)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for SessionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<SessionId> for Uuid {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

/// Per-request identity, cloned cheaply. `auth::middleware` attaches it to
/// request extensions for handlers and the audit layer. Manual `Debug` redacts
/// `user_email` (PII); the audit writer reads it directly, nothing else should.
#[derive(Clone)]
pub struct Identity {
    pub session_id: SessionId,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    /// When the gateway issued this session. Groups are frozen at this instant
    /// — a group change in the IdP takes effect only at the *next* login.
    /// Admin middleware uses this to enforce a `session_max_age_secs` bound so
    /// operators can cap how long a stale admin-group snapshot is trusted.
    pub issued_at: DateTime<Utc>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("session_id", &self.session_id)
            .field("user_sub", &self.user_sub)
            .field("user_email", &"<redacted>")
            .field("groups", &self.groups)
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

/// Authoritative session row. `Debug` redacts `user_email` (PII) — see
/// `Identity` above for the same rationale.
#[derive(Clone)]
pub struct Session {
    pub id: SessionId,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    pub agent_client: Option<String>,
    /// Wall-clock instant the gateway inserted this row (DB `DEFAULT now()`).
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("user_sub", &self.user_sub)
            .field("user_email", &"<redacted>")
            .field("groups", &self.groups)
            .field("agent_client", &self.agent_client)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl Session {
    pub fn identity(&self) -> Identity {
        Identity {
            session_id: self.id,
            user_sub: self.user_sub.clone(),
            user_email: self.user_email.clone(),
            groups: self.groups.clone(),
            issued_at: self.issued_at,
        }
    }

    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// Cache + DB. Cheap to clone — internal `Arc` shares the same cache and pool.
#[derive(Clone)]
pub struct SessionStore {
    pool: PgPool,
    cache: Arc<SessionCache>,
}

impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `PgPool` Debug leaks the DSN; the cache needs an async read.
        f.debug_struct("SessionStore")
            .field("pool", &"<PgPool>")
            .field("cache", &"<SessionCache>")
            .finish()
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

    /// Persist a new session row and warm the cache.
    pub async fn create(
        &self,
        user_sub: &str,
        user_email: &str,
        groups: &[String],
        ttl: std::time::Duration,
        agent_client: Option<&str>,
    ) -> Result<Session, AuthError> {
        let id = SessionId::new();
        let now = Utc::now();
        let expires_at = now + ChronoDuration::from_std(ttl).unwrap_or(ChronoDuration::hours(8));
        let groups_json = serde_json::to_value(groups).unwrap_or(serde_json::Value::Array(vec![]));

        sqlx::query(
            "INSERT INTO sessions (id, user_sub, user_email, groups, agent_client, \
             issued_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(Uuid::from(id))
        .bind(user_sub)
        .bind(user_email)
        .bind(&groups_json)
        .bind(agent_client)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        let session = Session {
            id,
            user_sub: user_sub.to_string(),
            user_email: user_email.to_string(),
            groups: groups.to_vec(),
            agent_client: agent_client.map(str::to_string),
            issued_at: now,
            expires_at,
            revoked_at: None,
        };
        self.cache.insert(id, session.clone()).await;
        // `active_sessions` only decrements on explicit revoke (natural expiry
        // drifts it up), so treat it as a floor on session count, not exact.
        metrics::gauge!("active_sessions").increment(1.0);
        Ok(session)
    }

    /// Resolve a session id to an Identity. Returns `RevokedSession` if the
    /// row exists but is revoked/expired, `InvalidSession` if missing.
    pub async fn lookup(&self, id: SessionId) -> Result<Identity, AuthError> {
        let now = Utc::now();
        // Fresh, active cache hit skips the DB. A stale hit (older than the
        // cache TTL) misses here and re-validates below — that re-read is what
        // lets a revoke on another replica take effect within the TTL.
        if let Some(session) = self.cache.get(id, now).await {
            return Ok(session.identity());
        }

        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_sub, user_email, groups, agent_client, \
             issued_at, expires_at, revoked_at \
             FROM sessions WHERE id = $1",
        )
        .bind(Uuid::from(id))
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            self.cache.remove(id).await;
            return Err(AuthError::InvalidSession);
        };
        let session: Session = row.into();
        if !session.is_active(now) {
            self.cache.remove(id).await;
            return Err(AuthError::RevokedSession);
        }
        self.cache.insert(id, session.clone()).await;
        Ok(session.identity())
    }

    /// Mark a session revoked in the DB and drop it from cache. Idempotent.
    pub async fn revoke(&self, id: SessionId) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(Uuid::from(id))
        .execute(&self.pool)
        .await?;
        self.cache.remove(id).await;
        // Decrement only on a real revoke — the `AND revoked_at IS NULL` guard
        // makes a double-logout a DB no-op, so the gauge can't go negative.
        if result.rows_affected() > 0 {
            metrics::gauge!("active_sessions").decrement(1.0);
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_sub: String,
    user_email: String,
    groups: serde_json::Value,
    agent_client: Option<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Self {
            id: SessionId::from(row.id),
            user_sub: row.user_sub,
            user_email: row.user_email,
            groups: serde_json::from_value(row.groups).unwrap_or_default(),
            agent_client: row.agent_client,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_session() -> Session {
        Session {
            id: SessionId::new(),
            user_sub: "sub".into(),
            user_email: "e@example.com".into(),
            groups: vec!["a".into(), "b".into()],
            agent_client: Some("claude-code/0.x".into()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            revoked_at: None,
        }
    }

    #[test]
    fn identity_clone_carries_fields() {
        let identity = base_session().identity();
        assert_eq!(identity.user_sub, "sub");
        assert_eq!(identity.groups, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn revoked_or_expired_is_inactive() {
        let now = Utc::now();
        let base = base_session();
        assert!(base.is_active(now));
        let revoked = Session {
            revoked_at: Some(now),
            ..base.clone()
        };
        assert!(!revoked.is_active(now));
        let expired = Session {
            issued_at: now - ChronoDuration::hours(2),
            expires_at: now - ChronoDuration::seconds(1),
            ..base
        };
        assert!(!expired.is_active(now));
    }
}
