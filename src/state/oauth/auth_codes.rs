//! One-time authorization codes (`oauth_auth_codes`, migration 0022). Queries
//! only — the TTL, cap and restore policy stay with `crate::auth::oauth`.

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{PgExecutor, PgPool};

/// A code row to write. `code_hash` is the SHA-256 of the code — the raw code
/// never reaches the DB.
pub struct NewAuthCode<'a> {
    pub code_hash: &'a [u8],
    pub user_sub: &'a str,
    pub email: &'a str,
    pub groups: &'a [String],
    pub code_challenge: &'a str,
    pub redirect_uri: &'a str,
    pub client_id: &'a str,
}

impl std::fmt::Debug for NewAuthCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: the hash is a lookup key and `email` is PII.
        f.debug_struct("NewAuthCode")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Insert a code expiring `ttl` from now (DB clock) unless `cap` live codes
/// already exist. `false` when the cap refused it; lapsed codes do not count
/// against it. The count and the insert run under one advisory lock, so
/// replicas racing for the last slot admit one code, not one each.
pub async fn insert_auth_code_capped(
    pool: &PgPool,
    code: &NewAuthCode<'_>,
    ttl: chrono::Duration,
    cap: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_auth_codes(&mut *tx).await?;
    let result = sqlx::query(
        "INSERT INTO oauth_auth_codes \
           (code_hash, user_sub, email, groups, code_challenge, redirect_uri, client_id, \
            expires_at) \
         SELECT $1, $2, $3, $4, $5, $6, $7, now() + $8 \
         WHERE (SELECT count(*) FROM oauth_auth_codes WHERE expires_at > now()) < $9",
    )
    .bind(code.code_hash)
    .bind(code.user_sub)
    .bind(code.email)
    .bind(Json(code.groups))
    .bind(code.code_challenge)
    .bind(code.redirect_uri)
    .bind(code.client_id)
    .bind(ttl)
    .bind(cap)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}

/// Put back a taken code with the deadline it was taken with, under the same
/// lock and `cap` as [`insert_auth_code_capped`]: the slot it held was freed
/// by the take and may since have gone to a new code. `false` when the cap
/// refused it. A code already back (or never gone) is left as it is and
/// counts as restored.
pub async fn restore_auth_code(
    pool: &PgPool,
    code: &NewAuthCode<'_>,
    expires_at: DateTime<Utc>,
    cap: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_auth_codes(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO oauth_auth_codes \
           (code_hash, user_sub, email, groups, code_challenge, redirect_uri, client_id, \
            expires_at) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
         WHERE (SELECT count(*) FROM oauth_auth_codes WHERE expires_at > now()) < $9 \
         ON CONFLICT (code_hash) DO NOTHING",
    )
    .bind(code.code_hash)
    .bind(code.user_sub)
    .bind(code.email)
    .bind(Json(code.groups))
    .bind(code.code_challenge)
    .bind(code.redirect_uri)
    .bind(code.client_id)
    .bind(expires_at)
    .bind(cap)
    .execute(&mut *tx)
    .await?;
    let present: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oauth_auth_codes WHERE code_hash = $1)")
            .bind(code.code_hash)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(present)
}

/// Serialises every admission to `oauth_auth_codes` across replicas until
/// the transaction ends.
async fn lock_auth_codes(conn: impl PgExecutor<'_>) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oauth_auth_codes', 0))")
        .execute(conn)
        .await?;
    Ok(())
}

/// A taken code. `groups` decodes through `Json`, so a malformed column is a
/// `sqlx::Error`, never a silently empty group list.
#[derive(sqlx::FromRow)]
pub struct AuthCodeRow {
    pub user_sub: String,
    pub email: String,
    pub groups: Json<Vec<String>>,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for AuthCodeRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `email` is PII and the challenge binds the code.
        f.debug_struct("AuthCodeRow")
            .field("user_sub", &self.user_sub)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Delete-and-return a live code in one statement, so of two concurrent
/// redemptions only one gets it. A lapsed row reads as absent, left for GC.
pub async fn take_auth_code(
    conn: impl PgExecutor<'_>,
    code_hash: &[u8],
) -> Result<Option<AuthCodeRow>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM oauth_auth_codes WHERE code_hash = $1 AND expires_at > now() \
         RETURNING user_sub, email, groups, code_challenge, redirect_uri, client_id, expires_at",
    )
    .bind(code_hash)
    .fetch_optional(conn)
    .await
}

/// Returns the number of rows deleted.
pub async fn delete_expired_auth_codes(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oauth_auth_codes WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
