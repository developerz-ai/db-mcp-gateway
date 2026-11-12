//! State-DB queries for gateway sessions (`sessions` table). Queries only —
//! caching, revocation semantics and metrics stay in `crate::auth::session`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// A session row to insert. `revoked_at` starts NULL.
pub struct NewSession<'a> {
    pub id: Uuid,
    pub user_sub: &'a str,
    pub user_email: &'a str,
    pub groups: &'a serde_json::Value,
    pub agent_client: Option<&'a str>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for NewSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `user_email` is PII.
        f.debug_struct("NewSession")
            .field("id", &self.id)
            .field("user_sub", &self.user_sub)
            .field("user_email", &"<redacted>")
            .field("groups", &self.groups)
            .field("agent_client", &self.agent_client)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A stored session row.
#[derive(sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_sub: String,
    pub user_email: String,
    pub groups: serde_json::Value,
    pub agent_client: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for SessionRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `user_email` is PII.
        f.debug_struct("SessionRow")
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

pub async fn insert(pool: &PgPool, session: &NewSession<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sessions (id, user_sub, user_email, groups, agent_client, \
         issued_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(session.id)
    .bind(session.user_sub)
    .bind(session.user_email)
    .bind(session.groups)
    .bind(session.agent_client)
    .bind(session.issued_at)
    .bind(session.expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn fetch(pool: &PgPool, id: Uuid) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, user_sub, user_email, groups, agent_client, \
         issued_at, expires_at, revoked_at \
         FROM sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Set `revoked_at` on a not-yet-revoked session. Returns rows affected: `0`
/// for an unknown or already-revoked session, so a double revoke is a no-op.
pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result =
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
            .bind(id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}
