//! State-DB queries for gateway sessions (`sessions` table). Queries only —
//! caching, revocation semantics and metrics stay in `crate::auth::session`.
//!
//! Writers take any `PgExecutor` so the OAuth rotation and the admin
//! revoke-sessions endpoint can run them inside their own transaction.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgExecutor;
use sqlx::types::Json;
use uuid::Uuid;

/// A session row to insert. `revoked_at` starts NULL.
pub struct NewSession<'a> {
    pub id: Uuid,
    pub user_sub: &'a str,
    pub user_email: &'a str,
    pub groups: &'a [String],
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
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A stored session row. `groups` decodes through `Json`, so a malformed
/// column is a `sqlx::Error`, never a silently empty group list.
#[derive(sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Json<Vec<String>>,
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
            .field("groups", &self.groups.0)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

pub async fn insert(
    conn: impl PgExecutor<'_>,
    session: &NewSession<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sessions (id, user_sub, user_email, groups, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(session.id)
    .bind(session.user_sub)
    .bind(session.user_email)
    .bind(Json(session.groups))
    .bind(session.issued_at)
    .bind(session.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn fetch(conn: impl PgExecutor<'_>, id: Uuid) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, user_sub, user_email, groups, issued_at, expires_at, revoked_at \
         FROM sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(conn)
    .await
}

/// Set `revoked_at` on a not-yet-revoked session. Returns rows affected: `0`
/// for an unknown or already-revoked session, so a double revoke is a no-op.
pub async fn revoke(conn: impl PgExecutor<'_>, id: Uuid) -> Result<u64, sqlx::Error> {
    let result =
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
            .bind(id)
            .execute(conn)
            .await?;
    Ok(result.rows_affected())
}

/// Revoke every live session of `user_sub`; returns the ids it revoked so the
/// caller can drop them from the in-process cache.
pub async fn revoke_all_for_sub(
    conn: impl PgExecutor<'_>,
    user_sub: &str,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE sessions SET revoked_at = now() \
         WHERE user_sub = $1 AND revoked_at IS NULL AND expires_at > now() \
         RETURNING id",
    )
    .bind(user_sub)
    .fetch_all(conn)
    .await
}

/// Delete rows that expired more than `grace` ago. A revoked row is kept until
/// it expires: until then it is the denylist entry for a still-signed JWT.
/// Uses `sessions_expires_at_idx`.
pub async fn delete_expired(
    conn: impl PgExecutor<'_>,
    grace: Duration,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < now() - $1")
        .bind(grace)
        .execute(conn)
        .await?;
    Ok(result.rows_affected())
}
