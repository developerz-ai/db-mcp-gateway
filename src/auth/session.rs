//! Sessions: the authoritative identity for an authenticated request.
//!
//! `SessionStore` fronts the state DB with an in-memory cache. Every lookup
//! goes through here so revocation is honored: logout removes from cache AND
//! sets `revoked_at` in the DB; lookup checks both.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::errors::AuthError;

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

/// Per-request identity. Cloned cheaply (groups is small, strings are short).
/// What `auth::middleware` attaches to the request extensions for handlers and
/// the audit layer to read.
///
/// Manual `Debug` redacts `user_email` (PII). The audit writer reads the field
/// directly; nothing else should log it.
#[derive(Clone)]
pub struct Identity {
    pub session_id: SessionId,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("session_id", &self.session_id)
            .field("user_sub", &self.user_sub)
            .field("user_email", &"<redacted>")
            .field("groups", &self.groups)
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
        }
    }

    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// Cache + DB. Cheap to clone — internal `Arc` shares the same map and pool.
#[derive(Clone)]
pub struct SessionStore {
    pool: PgPool,
    cache: Arc<RwLock<HashMap<SessionId, Session>>>,
}

impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `PgPool` Debug leaks the connection string, and reading
        // the cache here would need an async lock. Print structural info only.
        f.debug_struct("SessionStore")
            .field("pool", &"<PgPool>")
            .field("cache", &"<RwLock<HashMap<SessionId, Session>>>")
            .finish()
    }
}

impl SessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
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
            expires_at,
            revoked_at: None,
        };
        self.cache.write().await.insert(id, session.clone());
        // `active_sessions` drifts on natural TTL expiry — only explicit
        // revoke decrements. Operators reading this should treat it as a
        // floor on real session count, not an exact number.
        metrics::gauge!("active_sessions").increment(1.0);
        Ok(session)
    }

    /// Resolve a session id to an Identity. Returns `RevokedSession` if the
    /// row exists but is revoked/expired, `InvalidSession` if missing.
    pub async fn lookup(&self, id: SessionId) -> Result<Identity, AuthError> {
        let now = Utc::now();

        if let Some(session) = self.cache.read().await.get(&id).cloned()
            && session.is_active(now)
        {
            return Ok(session.identity());
        }

        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_sub, user_email, groups, agent_client, expires_at, revoked_at \
             FROM sessions WHERE id = $1",
        )
        .bind(Uuid::from(id))
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            self.cache.write().await.remove(&id);
            return Err(AuthError::InvalidSession);
        };
        let session: Session = row.into();
        if !session.is_active(now) {
            self.cache.write().await.remove(&id);
            return Err(AuthError::RevokedSession);
        }
        self.cache.write().await.insert(id, session.clone());
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
        self.cache.write().await.remove(&id);
        // Only decrement on real revocation — the `AND revoked_at IS NULL`
        // guard makes a double-logout a no-op at the DB, and we mirror that
        // here so the gauge can't go negative on idempotent revoke calls.
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
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        let groups: Vec<String> = serde_json::from_value(row.groups).unwrap_or_default();
        Self {
            id: SessionId::from(row.id),
            user_sub: row.user_sub,
            user_email: row.user_email,
            groups,
            agent_client: row.agent_client,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_clone_carries_fields() {
        let session = Session {
            id: SessionId::new(),
            user_sub: "sub".into(),
            user_email: "e@example.com".into(),
            groups: vec!["a".into(), "b".into()],
            agent_client: Some("claude-code/0.x".into()),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            revoked_at: None,
        };
        let identity = session.identity();
        assert_eq!(identity.user_sub, "sub");
        assert_eq!(identity.groups, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn revoked_or_expired_is_inactive() {
        let now = Utc::now();
        let base = Session {
            id: SessionId::new(),
            user_sub: "s".into(),
            user_email: "e".into(),
            groups: vec![],
            agent_client: None,
            expires_at: now + ChronoDuration::hours(1),
            revoked_at: None,
        };
        assert!(base.is_active(now));
        let revoked = Session {
            revoked_at: Some(now),
            ..base.clone()
        };
        assert!(!revoked.is_active(now));
        let expired = Session {
            expires_at: now - ChronoDuration::seconds(1),
            ..base
        };
        assert!(!expired.is_active(now));
    }
}
