//! Dynamic-Client-Registration queries (`oauth_clients`, migration 0008;
//! `client_name`, migration 0019).
//!
//! `client_name` is nullable and every write names its columns, so release
//! N-1 (which knows nothing of it) still inserts and reads on this schema.

use sqlx::types::Json;
use sqlx::{PgExecutor, PgPool};

/// A live registration as read back by [`find_client`].
#[derive(Debug, sqlx::FromRow)]
pub struct ClientRow {
    pub redirect_uris: Json<Vec<String>>,
    /// Self-asserted at `/register`; `NULL` for adopted clients and rows
    /// written before 0019 or by release N-1.
    pub client_name: Option<String>,
}

/// Rows a capped client insert may evict: expired, or never authorised
/// (`expires_at` still within `unused_ttl` of `created_at` — a completed
/// login slides it far past that).
const EVICTABLE_CLIENT: &str = "expires_at <= now() OR expires_at <= created_at + $4";

/// Returns the number of rows deleted.
pub async fn delete_expired_clients(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oauth_clients WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// What a capped insert does to a still-live row with the same `client_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveClient {
    /// `/register`: the caller owns the id it was just issued.
    Replace,
    /// `/authorize` adoption: the id is caller-chosen, so an existing live
    /// registration's redirect URIs must survive it.
    Keep,
}

/// Register a client with the never-authorised TTL, in one statement.
///
/// A row that already holds `client_id` is resolved first, on the same
/// snapshot as everything else: lapsed and not yet GC'd, it is reset as if
/// new (so `/authorize` adoption of a cached id can revive it); live, it
/// keeps its expiry and, per `live`, either takes the new URIs and name or
/// is left untouched (`false`). Either way nothing is evicted — the row is
/// written in place or not at all.
///
/// Only a new `client_id` needs room: at `cap` rows it evicts the oldest
/// evictable row, and is refused (`false`) when none is evictable.
pub async fn insert_client_capped(
    conn: impl PgExecutor<'_>,
    client_id: &str,
    redirect_uris: &[String],
    client_name: Option<&str>,
    cap: i64,
    unused_ttl: chrono::Duration,
    live: LiveClient,
) -> Result<bool, sqlx::Error> {
    let (unless_live, only_lapsed) = match live {
        LiveClient::Replace => ("", ""),
        LiveClient::Keep => (
            "NOT EXISTS (SELECT 1 FROM target WHERE live) AND ",
            // A row a concurrent insert committed after this snapshot.
            " WHERE oauth_clients.expires_at <= now()",
        ),
    };
    let sql = format!(
        "WITH target AS ( \
           SELECT expires_at > now() AS live FROM oauth_clients WHERE client_id = $1), \
         evicted AS ( \
           DELETE FROM oauth_clients WHERE NOT EXISTS (SELECT 1 FROM target) \
             AND client_id IN ( \
               SELECT client_id FROM oauth_clients WHERE {EVICTABLE_CLIENT} \
               ORDER BY created_at \
               LIMIT GREATEST((SELECT count(*) FROM oauth_clients) - $3 + 1, 0)) \
           RETURNING 1) \
         INSERT INTO oauth_clients (client_id, redirect_uris, client_name, expires_at) \
         SELECT $1, $2, $5, now() + $4 \
         WHERE {unless_live}(EXISTS (SELECT 1 FROM target) \
           OR (SELECT count(*) FROM oauth_clients) - (SELECT count(*) FROM evicted) < $3) \
         ON CONFLICT (client_id) DO UPDATE SET \
           redirect_uris = EXCLUDED.redirect_uris, \
           client_name = EXCLUDED.client_name, \
           created_at = CASE WHEN oauth_clients.expires_at <= now() \
             THEN EXCLUDED.created_at ELSE oauth_clients.created_at END, \
           expires_at = CASE WHEN oauth_clients.expires_at <= now() \
             THEN EXCLUDED.expires_at ELSE oauth_clients.expires_at END\
         {only_lapsed}"
    );
    let result = sqlx::query(&sql)
        .bind(client_id)
        .bind(Json(redirect_uris))
        .bind(cap)
        .bind(unused_ttl)
        .bind(client_name)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// The live client; `None` when absent or expired. Read-only: `/authorize`
/// is unauthenticated, so resolving a client must not extend its lifetime.
pub async fn find_client(pool: &PgPool, client_id: &str) -> Result<Option<ClientRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT redirect_uris, client_name FROM oauth_clients \
         WHERE client_id = $1 AND expires_at > now()",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
}

/// Slide a live client's `expires_at` to `now() + ttl`. `false` when absent
/// or expired.
pub async fn promote_client(
    pool: &PgPool,
    client_id: &str,
    ttl: chrono::Duration,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_clients SET expires_at = now() + $2 \
         WHERE client_id = $1 AND expires_at > now()",
    )
    .bind(client_id)
    .bind(ttl)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
