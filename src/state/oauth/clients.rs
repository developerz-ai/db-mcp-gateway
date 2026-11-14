//! Dynamic-Client-Registration queries (`oauth_clients`, migration 0008;
//! `client_name`, migration 0019).
//!
//! `client_name` is nullable and every write names its columns, so release
//! N-1 (which knows nothing of it) still inserts and reads on this schema.

use sqlx::types::Json;
use sqlx::{PgExecutor, PgPool};

/// A live registration as read back by [`touch_client`].
#[derive(Debug, sqlx::FromRow)]
pub struct ClientRow {
    pub redirect_uris: Json<Vec<String>>,
    /// Self-asserted at `/register`; `NULL` for adopted clients and rows
    /// written before 0019 or by release N-1.
    pub client_name: Option<String>,
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
/// replaces its URIs and name and keeps a live row's expiry; a lapsed,
/// not-yet-GC'd row is reset as if new, so `/authorize` adoption of a cached
/// id can revive it. At the cap it needs the same room as a new client.
pub async fn insert_client_capped(
    conn: impl PgExecutor<'_>,
    client_id: &str,
    redirect_uris: &[String],
    client_name: Option<&str>,
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
         INSERT INTO oauth_clients (client_id, redirect_uris, client_name, expires_at) \
         SELECT $1, $2, $5, now() + $4 \
         WHERE (SELECT count(*) FROM oauth_clients) - (SELECT count(*) FROM evicted) < $3 \
         ON CONFLICT (client_id) DO UPDATE SET \
           redirect_uris = EXCLUDED.redirect_uris, \
           client_name = EXCLUDED.client_name, \
           created_at = CASE WHEN oauth_clients.expires_at <= now() \
             THEN EXCLUDED.created_at ELSE oauth_clients.created_at END, \
           expires_at = CASE WHEN oauth_clients.expires_at <= now() \
             THEN EXCLUDED.expires_at ELSE oauth_clients.expires_at END"
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

/// The live client, sliding its `expires_at` to `now() + ttl` in the same
/// statement so the read and the renewal can't disagree. `None` when absent or
/// expired.
pub async fn touch_client(
    pool: &PgPool,
    client_id: &str,
    ttl: chrono::Duration,
) -> Result<Option<ClientRow>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE oauth_clients SET expires_at = now() + $2 \
         WHERE client_id = $1 AND expires_at > now() \
         RETURNING redirect_uris, client_name",
    )
    .bind(client_id)
    .bind(ttl)
    .fetch_optional(pool)
    .await
}
