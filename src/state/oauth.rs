//! State-DB queries for the OAuth bridge: refresh-token chains
//! (`oauth_refresh_tokens`, migration 0009; rotated-token tombstones in
//! `oauth_refresh_rotated`, migration 0017) and Dynamic-Client-Registration
//! clients (`oauth_clients`, migrations 0008 and 0019, in [`clients`]). Queries only — TTL, cap and
//! fail-closed policy stay with the callers in `crate::auth::oauth`.
//!
//! Every function returns the raw `sqlx::Error`; callers must never render it,
//! because its `Display` can embed the DSN (see `state::connect`).

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

mod clients;

pub use clients::{ClientRow, delete_expired_clients, insert_client_capped, touch_client};

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
    /// Stable across rotations; reuse detection revokes by it (migration 0017).
    pub chain_id: Uuid,
}

impl std::fmt::Debug for NewRefreshToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: the token hash is a lookup key and `email` is PII.
        f.debug_struct("NewRefreshToken")
            .field("user_sub", &self.user_sub)
            .field("chain_issued_at", &self.chain_issued_at)
            .field("expires_at", &self.expires_at)
            .field("session_id", &self.session_id)
            .field("chain_id", &self.chain_id)
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
    pub chain_id: Uuid,
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
            .field("chain_id", &self.chain_id)
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
           (token_hash, user_sub, email, groups, chain_issued_at, expires_at, session_id, \
            chain_id) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $9 \
         WHERE (SELECT count(*) FROM oauth_refresh_tokens) < $8 \
         ON CONFLICT (token_hash) DO UPDATE \
           SET user_sub = EXCLUDED.user_sub, \
               email = EXCLUDED.email, \
               groups = EXCLUDED.groups, \
               chain_issued_at = EXCLUDED.chain_issued_at, \
               expires_at = EXCLUDED.expires_at, \
               session_id = EXCLUDED.session_id, \
               chain_id = EXCLUDED.chain_id",
    )
    .bind(token.token_hash)
    .bind(token.user_sub)
    .bind(token.email)
    .bind(Json(token.groups))
    .bind(token.chain_issued_at)
    .bind(token.expires_at)
    .bind(token.session_id)
    .bind(cap)
    .bind(token.chain_id)
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
         RETURNING user_sub, email, groups, chain_issued_at, session_id, chain_id",
    )
    .bind(token_hash)
    .fetch_optional(conn)
    .await
}

/// Serialise every rotation and reuse-revocation of `chain_id` until the
/// transaction ends. Without it, a revocation racing an uncommitted rotation
/// waits on the old token's row lock and never sees the new token.
pub async fn lock_chain(conn: impl PgExecutor<'_>, chain_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oauth_refresh_chain:' || $1, 0))")
        .bind(chain_id.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

/// The chain of a live (not yet rotated-out) token, if any. Read before
/// [`lock_chain`] so the rotation can lock before it consumes the token.
pub async fn live_chain(
    conn: impl PgExecutor<'_>,
    token_hash: &[u8],
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT chain_id FROM oauth_refresh_tokens WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(token_hash)
    .fetch_optional(conn)
    .await
}

/// [`take_refresh_token`] for a rotation: the consumed hash is also
/// tombstoned until the chain's expiry, in the same statement, so a later
/// presentation is recognisable as reuse.
pub async fn rotate_out_refresh_token(
    conn: impl PgExecutor<'_>,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as(
        "WITH taken AS ( \
           DELETE FROM oauth_refresh_tokens \
           WHERE token_hash = $1 AND expires_at > now() \
           RETURNING *), \
         tombstone AS ( \
           INSERT INTO oauth_refresh_rotated (token_hash, chain_id, expires_at) \
           SELECT token_hash, chain_id, expires_at FROM taken \
           ON CONFLICT (token_hash) DO UPDATE \
             SET chain_id = EXCLUDED.chain_id, expires_at = EXCLUDED.expires_at, \
                 rotated_at = EXCLUDED.rotated_at) \
         SELECT user_sub, email, groups, chain_issued_at, session_id, chain_id FROM taken",
    )
    .bind(token_hash)
    .fetch_optional(conn)
    .await
}

/// The live chain a tombstoned (already rotated-out) `token_hash` belongs to,
/// if it was rotated out more than `grace` ago. `None` for an unknown hash, a
/// lapsed chain, or a rotation still inside `grace`.
pub async fn rotated_chain(
    conn: impl PgExecutor<'_>,
    token_hash: &[u8],
    grace: chrono::Duration,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT chain_id FROM oauth_refresh_rotated \
         WHERE token_hash = $1 AND expires_at > now() AND rotated_at <= now() - $2",
    )
    .bind(token_hash)
    .bind(grace)
    .fetch_optional(conn)
    .await
}

/// Delete every live token of `chain_id`; returns their paired sessions so
/// the caller revokes them in the same transaction.
pub async fn delete_chain(
    conn: impl PgExecutor<'_>,
    chain_id: Uuid,
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar("DELETE FROM oauth_refresh_tokens WHERE chain_id = $1 RETURNING session_id")
        .bind(chain_id)
        .fetch_all(conn)
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

/// Sweeps lapsed tombstones too; returns the number of token rows deleted.
pub async fn delete_expired_refresh_tokens(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "WITH tombstones AS (DELETE FROM oauth_refresh_rotated WHERE expires_at <= now()) \
         DELETE FROM oauth_refresh_tokens WHERE expires_at <= now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
