//! State-DB queries for the OAuth bridge: refresh-token chains
//! (`oauth_refresh_tokens`, migration 0009) and Dynamic-Client-Registration
//! clients (`oauth_clients`, migration 0008). Queries only — TTL, cap and
//! fail-closed policy stay with the callers in `crate::auth::oauth`.
//!
//! Every function returns the raw `sqlx::Error`; callers must never render it,
//! because its `Display` can embed the DSN (see `state::connect`).

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// A refresh-token row to upsert. `token_hash` is the SHA-256 of the bearer
/// value — the raw token never reaches the DB.
pub struct NewRefreshToken<'a> {
    pub token_hash: &'a [u8],
    pub user_sub: &'a str,
    pub email: &'a str,
    pub groups: &'a serde_json::Value,
    pub chain_issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for NewRefreshToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: the token hash is a lookup key and `email` is PII.
        f.debug_struct("NewRefreshToken")
            .field("user_sub", &self.user_sub)
            .field("chain_issued_at", &self.chain_issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// A redeemed refresh-token row.
#[derive(sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub user_sub: String,
    pub email: String,
    pub groups: serde_json::Value,
    pub chain_issued_at: DateTime<Utc>,
}

impl std::fmt::Debug for RefreshTokenRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `email` is PII.
        f.debug_struct("RefreshTokenRow")
            .field("user_sub", &self.user_sub)
            .field("email", &"<redacted>")
            .field("groups", &self.groups)
            .field("chain_issued_at", &self.chain_issued_at)
            .finish()
    }
}

pub async fn refresh_token_exists(pool: &PgPool, token_hash: &[u8]) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT exists(SELECT 1 FROM oauth_refresh_tokens WHERE token_hash = $1)")
        .bind(token_hash)
        .fetch_one(pool)
        .await
}

pub async fn count_refresh_tokens(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM oauth_refresh_tokens")
        .fetch_one(pool)
        .await
}

pub async fn upsert_refresh_token(
    pool: &PgPool,
    token: &NewRefreshToken<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens \
           (token_hash, user_sub, email, groups, chain_issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (token_hash) DO UPDATE \
           SET user_sub = EXCLUDED.user_sub, \
               email = EXCLUDED.email, \
               groups = EXCLUDED.groups, \
               chain_issued_at = EXCLUDED.chain_issued_at, \
               expires_at = EXCLUDED.expires_at",
    )
    .bind(token.token_hash)
    .bind(token.user_sub)
    .bind(token.email)
    .bind(token.groups)
    .bind(token.chain_issued_at)
    .bind(token.expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete-and-return a live token in one statement, so a concurrent replay of
/// the same token can only win once (rotation must be single-use). A lapsed
/// row is reported as absent and left for GC.
pub async fn take_refresh_token(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM oauth_refresh_tokens \
         WHERE token_hash = $1 AND expires_at > now() \
         RETURNING user_sub, email, groups, chain_issued_at",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Returns the number of rows deleted.
pub async fn delete_refresh_tokens_for_sub(pool: &PgPool, sub: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(sub)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delete_expired_refresh_tokens(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_expired_clients(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_clients WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn client_exists(pool: &PgPool, client_id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT exists(SELECT 1 FROM oauth_clients WHERE client_id = $1)")
        .bind(client_id)
        .fetch_one(pool)
        .await
}

pub async fn count_clients(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
        .fetch_one(pool)
        .await
}

pub async fn upsert_client(
    pool: &PgPool,
    client_id: &str,
    redirect_uris: &serde_json::Value,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, expires_at) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (client_id) DO UPDATE \
           SET redirect_uris = EXCLUDED.redirect_uris, expires_at = EXCLUDED.expires_at",
    )
    .bind(client_id)
    .bind(redirect_uris)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// The live client's `redirect_uris` JSON, sliding its `expires_at` to
/// `new_expires_at` in the same statement so the read and the renewal can't
/// disagree. `None` when absent or expired.
pub async fn touch_client(
    pool: &PgPool,
    client_id: &str,
    new_expires_at: DateTime<Utc>,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE oauth_clients SET expires_at = $2 \
         WHERE client_id = $1 AND expires_at > now() \
         RETURNING redirect_uris",
    )
    .bind(client_id)
    .bind(new_expires_at)
    .fetch_optional(pool)
    .await
}
