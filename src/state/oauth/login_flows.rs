//! Pending IdP logins (`oauth_pending_flows`) and consents awaiting a decision
//! (`oauth_pending_consents`), migration 0022. Queries only — TTLs, caps and
//! the bridge's JSON shape stay with `crate::auth::oauth`.

use sqlx::types::Json;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

/// Insert a pending login, first evicting the soonest-expiring flows so the
/// table stays under `cap`: `/authorize` is unauthenticated, so refusing at
/// the cap would let a flood block every real login. An advisory lock held to
/// commit serialises flow inserts across replicas: without it racing inserts
/// each count the same snapshot and the table overshoots `cap` by their number.
pub async fn insert_flow(
    pool: &PgPool,
    state_hash: &[u8],
    bridge: Option<&serde_json::Value>,
    ttl: chrono::Duration,
    cap: i64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oauth_pending_flows', 0))")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "WITH evicted AS ( \
           DELETE FROM oauth_pending_flows WHERE state_hash IN ( \
             SELECT state_hash FROM oauth_pending_flows ORDER BY expires_at \
             LIMIT greatest(0, (SELECT count(*) FROM oauth_pending_flows) - ($4 - 1)))) \
         INSERT INTO oauth_pending_flows (state_hash, bridge, expires_at) \
         VALUES ($1, $2, now() + $3) \
         ON CONFLICT (state_hash) DO UPDATE \
           SET bridge = EXCLUDED.bridge, expires_at = EXCLUDED.expires_at",
    )
    .bind(state_hash)
    .bind(bridge.map(Json))
    .bind(ttl)
    .bind(cap)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Delete-and-return a live flow's bridge context in one statement, so only
/// one of two concurrent callbacks with the same `state` gets it. `Some(None)`
/// is a live `/auth/login` flow (no bridge). A lapsed row reads as absent and
/// is left for GC.
pub async fn take_flow(
    conn: impl PgExecutor<'_>,
    state_hash: &[u8],
) -> Result<Option<Option<serde_json::Value>>, sqlx::Error> {
    let row: Option<(Option<Json<serde_json::Value>>,)> = sqlx::query_as(
        "DELETE FROM oauth_pending_flows WHERE state_hash = $1 AND expires_at > now() \
         RETURNING bridge",
    )
    .bind(state_hash)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(bridge,)| bridge.map(|Json(value)| value)))
}

/// A consent row to insert; the digests stand in for the consent id and CSRF.
pub struct NewConsent<'a> {
    pub consent_hash: &'a [u8],
    pub csrf_hash: &'a [u8],
    pub user_sub: &'a str,
    pub email: &'a str,
    pub groups: &'a [String],
    pub bridge: &'a serde_json::Value,
}

impl std::fmt::Debug for NewConsent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: the digests are lookup keys and `email` is PII.
        f.debug_struct("NewConsent").finish_non_exhaustive()
    }
}

/// Caps for [`insert_consent`].
#[derive(Debug, Clone, Copy)]
pub struct ConsentCaps {
    pub per_subject: i64,
    pub total: i64,
}

/// Insert a consent, first evicting the subject's soonest-expiring consents
/// down to `per_subject - 1` and then the table's down to `total - 1`, in
/// `tx` so the evictions and the insert land together. An advisory lock held
/// to the end of `tx` serialises consent inserts across replicas: without it
/// two racing inserts each evict for themselves and both caps overshoot.
pub async fn insert_consent(
    tx: &mut Transaction<'_, Postgres>,
    consent: &NewConsent<'_>,
    ttl: chrono::Duration,
    caps: ConsentCaps,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oauth_pending_consents', 0))")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "DELETE FROM oauth_pending_consents WHERE consent_hash IN ( \
           SELECT consent_hash FROM oauth_pending_consents WHERE user_sub = $1 \
           ORDER BY expires_at DESC OFFSET greatest(0, $2 - 1))",
    )
    .bind(consent.user_sub)
    .bind(caps.per_subject)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM oauth_pending_consents WHERE consent_hash IN ( \
           SELECT consent_hash FROM oauth_pending_consents ORDER BY expires_at \
           LIMIT greatest(0, (SELECT count(*) FROM oauth_pending_consents) - ($1 - 1)))",
    )
    .bind(caps.total)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO oauth_pending_consents \
           (consent_hash, csrf_hash, user_sub, email, groups, bridge, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now() + $7)",
    )
    .bind(consent.consent_hash)
    .bind(consent.csrf_hash)
    .bind(consent.user_sub)
    .bind(consent.email)
    .bind(Json(consent.groups))
    .bind(Json(consent.bridge))
    .bind(ttl)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A taken consent. `groups` and `bridge` decode through `Json`, so a
/// malformed column is a `sqlx::Error`, never a silently empty value.
#[derive(sqlx::FromRow)]
pub struct ConsentRow {
    pub csrf_hash: Vec<u8>,
    pub user_sub: String,
    pub email: String,
    pub groups: Json<Vec<String>>,
    pub bridge: Json<serde_json::Value>,
}

impl std::fmt::Debug for ConsentRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: the CSRF digest is a bearer stand-in and `email` is PII.
        f.debug_struct("ConsentRow")
            .field("user_sub", &self.user_sub)
            .finish_non_exhaustive()
    }
}

/// Delete-and-return a live consent in one statement: single-use, whatever
/// the decision or CSRF check that follows.
pub async fn take_consent(
    conn: impl PgExecutor<'_>,
    consent_hash: &[u8],
) -> Result<Option<ConsentRow>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM oauth_pending_consents WHERE consent_hash = $1 AND expires_at > now() \
         RETURNING csrf_hash, user_sub, email, groups, bridge",
    )
    .bind(consent_hash)
    .fetch_optional(conn)
    .await
}

/// Delete lapsed flows and consents; returns how many rows went.
pub async fn delete_expired_login_flows(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let flows = sqlx::query("DELETE FROM oauth_pending_flows WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    let consents = sqlx::query("DELETE FROM oauth_pending_consents WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(flows.rows_affected() + consents.rows_affected())
}
