//! State-DB queries for the OAuth bridge: refresh-token chains
//! (`oauth_refresh_tokens`, migration 0009) and Dynamic-Client-Registration
//! clients (`oauth_clients`, migration 0008). Queries only — TTL, cap and
//! fail-closed policy stay with the callers in `crate::auth::oauth`.
//!
//! Every function returns the raw `sqlx::Error`; callers must never render it,
//! because its `Display` can embed the DSN (see `state::connect`).

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

/// A refresh-token row to upsert. `token_hash` is the SHA-256 of the bearer
/// value — the raw token never reaches the DB.
pub struct NewRefreshToken<'a> {
    pub token_hash: &'a [u8],
    pub user_sub: &'a str,
    pub email: &'a str,
    pub groups: &'a [String],
    pub chain_issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The access session minted alongside this token (migration 0012).
    pub session_id: Option<Uuid>,
}

impl std::fmt::Debug for NewRefreshToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: the token hash is a lookup key and `email` is PII.
        f.debug_struct("NewRefreshToken")
            .field("user_sub", &self.user_sub)
            .field("chain_issued_at", &self.chain_issued_at)
            .field("expires_at", &self.expires_at)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// A redeemed refresh-token row. `groups` decodes through `Json`, so a
/// malformed column is a `sqlx::Error`, never a silently empty group list.
#[derive(sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub user_sub: String,
    pub email: String,
    pub groups: Json<Vec<String>>,
    pub chain_issued_at: DateTime<Utc>,
    pub session_id: Option<Uuid>,
}

impl std::fmt::Debug for RefreshTokenRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `email` is PII.
        f.debug_struct("RefreshTokenRow")
            .field("user_sub", &self.user_sub)
            .field("email", &"<redacted>")
            .field("groups", &self.groups.0)
            .field("chain_issued_at", &self.chain_issued_at)
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// Insert a refresh token unless the table already holds `cap` rows, in one
/// statement. `false` when the cap refused it. A same-hash conflict updates
/// the row (only reachable below the cap).
pub async fn insert_refresh_token_capped(
    conn: impl PgExecutor<'_>,
    token: &NewRefreshToken<'_>,
    cap: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO oauth_refresh_tokens \
           (token_hash, user_sub, email, groups, chain_issued_at, expires_at, session_id) \
         SELECT $1, $2, $3, $4, $5, $6, $7 \
         WHERE (SELECT count(*) FROM oauth_refresh_tokens) < $8 \
         ON CONFLICT (token_hash) DO UPDATE \
           SET user_sub = EXCLUDED.user_sub, \
               email = EXCLUDED.email, \
               groups = EXCLUDED.groups, \
               chain_issued_at = EXCLUDED.chain_issued_at, \
               expires_at = EXCLUDED.expires_at, \
               session_id = EXCLUDED.session_id",
    )
    .bind(token.token_hash)
    .bind(token.user_sub)
    .bind(token.email)
    .bind(Json(token.groups))
    .bind(token.chain_issued_at)
    .bind(token.expires_at)
    .bind(token.session_id)
    .bind(cap)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete-and-return a live token in one statement, so a concurrent replay of
/// the same token can only win once (rotation must be single-use). A lapsed
/// row is reported as absent and left for GC.
pub async fn take_refresh_token(
    conn: impl PgExecutor<'_>,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM oauth_refresh_tokens \
         WHERE token_hash = $1 AND expires_at > now() \
         RETURNING user_sub, email, groups, chain_issued_at, session_id",
    )
    .bind(token_hash)
    .fetch_optional(conn)
    .await
}

/// Returns the number of rows deleted.
pub async fn delete_refresh_tokens_for_sub(
    conn: impl PgExecutor<'_>,
    sub: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(sub)
        .execute(conn)
        .await?;
    Ok(result.rows_affected())
}

/// Returns the number of rows deleted.
pub async fn delete_expired_refresh_tokens(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oauth_refresh_tokens WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Rows a capped client insert may evict: expired, or never authorised
/// (`expires_at` still within `unused_ttl` of `created_at` — a successful
/// `/authorize` slides it far past that).
const EVICTABLE_CLIENT: &str = "expires_at <= now() OR expires_at <= created_at + $4";

/// Returns the number of rows deleted.
pub async fn delete_expired_clients(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oauth_clients WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Register a client with the never-authorised TTL, in one statement. At
/// `cap` rows it first evicts the oldest evictable row; if none is evictable
/// the insert is refused (`false`). Re-registering an existing `client_id`
/// replaces its URIs and keeps its expiry; at the cap it needs the same room
/// as a new client.
pub async fn insert_client_capped(
    conn: impl PgExecutor<'_>,
    client_id: &str,
    redirect_uris: &[String],
    cap: i64,
    unused_ttl: chrono::Duration,
) -> Result<bool, sqlx::Error> {
    let sql = format!(
        "WITH evicted AS ( \
           DELETE FROM oauth_clients WHERE client_id IN ( \
             SELECT client_id FROM oauth_clients WHERE {EVICTABLE_CLIENT} \
             ORDER BY created_at \
             LIMIT GREATEST((SELECT count(*) FROM oauth_clients) - $3 + 1, 0)) \
           RETURNING 1) \
         INSERT INTO oauth_clients (client_id, redirect_uris, expires_at) \
         SELECT $1, $2, now() + $4 \
         WHERE (SELECT count(*) FROM oauth_clients) - (SELECT count(*) FROM evicted) < $3 \
         ON CONFLICT (client_id) DO UPDATE SET redirect_uris = EXCLUDED.redirect_uris"
    );
    let result = sqlx::query(&sql)
        .bind(client_id)
        .bind(Json(redirect_uris))
        .bind(cap)
        .bind(unused_ttl)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// The live client's redirect URIs, sliding its `expires_at` to `now() + ttl`
/// in the same statement so the read and the renewal can't disagree. `None`
/// when absent or expired.
pub async fn touch_client(
    pool: &PgPool,
    client_id: &str,
    ttl: chrono::Duration,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    let uris: Option<Json<Vec<String>>> = sqlx::query_scalar(
        "UPDATE oauth_clients SET expires_at = now() + $2 \
         WHERE client_id = $1 AND expires_at > now() \
         RETURNING redirect_uris",
    )
    .bind(client_id)
    .bind(ttl)
    .fetch_optional(pool)
    .await?;
    Ok(uris.map(|Json(uris)| uris))
}
