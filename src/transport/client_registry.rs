//! Dynamic-Client-Registration store for the MCP OAuth bridge.
//!
//! `POST /register` records a client's redirect-URI allowlist here under a
//! generated `client_id`; `/authorize` later matches the requested
//! `redirect_uri` against this set exactly (OAuth 2.1 redirect allowlist /
//! RFC 8252). Bounded (TTL + hard cap) because `/register` is unauthenticated.
//!
//! Two backends behind one API:
//! - **DB** (`with_db`) — the production path. Registrations live in the shared
//!   state DB (`oauth_clients`, migration 0008), so a pod restart / redeploy no
//!   longer wipes them. That wipe was the `invalid_client` wedge: a client that
//!   caches its `client_id` (most do) replayed a now-forgotten id after every
//!   deploy and got a hard error instead of silently re-registering. Persisting
//!   matches how `sessions` already survive restarts.
//! - **Memory** (`default`) — the auth-less test bootstrap (`AppState::for_tests`)
//!   and unit tests, which have no state DB.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;

/// TTL for a Dynamic-Client-Registration entry. A client registers, then walks
/// `/authorize` → `/token` right away and only re-authorizes on a full browser
/// re-login (refresh covers the common renewal), so the entry need only outlive
/// that. Persisted in the DB backend (survives restarts) and time-bounded in the
/// memory backend; either way a lapsed entry is GC'd and a spec-compliant client
/// re-registers on the next `invalid_client`.
const CLIENT_TTL: Duration = Duration::from_secs(24 * 3600);

/// Hard cap on registered clients. `/register` is unauthenticated (open DCR per
/// RFC 7591), so the store needs a ceiling or a flood could exhaust it. At the
/// cap (after GC drops expired entries) a new registration is *rejected* rather
/// than evicting a live client: evicting the soonest-to-expire entry would let
/// an unauthenticated flood knock legitimate clients out of their in-flight
/// `/authorize` (`invalid_client`). Bounded storage that still self-heals as
/// TTLs lapse.
const CLIENT_CAP: i64 = 10_000;

/// Bounded registry of Dynamic-Client-Registration clients: `client_id` → its
/// registered redirect URIs. `/authorize` matches the requested `redirect_uri`
/// against this set exactly, so a client can only be sent an authorization code
/// at a URI it pre-registered (OAuth 2.1 redirect allowlist / RFC 8252).
#[derive(Clone)]
pub struct ClientRegistry {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    /// Shared state DB (`oauth_clients`). Production.
    Db(PgPool),
    /// In-process map. Test bootstrap only (no state DB).
    Memory(Arc<Mutex<HashMap<String, RegisteredClient>>>),
}

impl std::fmt::Debug for ClientRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `PgPool`'s Debug can render the DSN (password). Never let
        // it reach a log line — see the same guard on `SessionStore`.
        let backend = match &self.backend {
            Backend::Db(_) => "Db(<PgPool>)",
            Backend::Memory(_) => "Memory",
        };
        f.debug_struct("ClientRegistry")
            .field("backend", &backend)
            .finish()
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self {
            backend: Backend::Memory(Arc::new(Mutex::new(HashMap::new()))),
        }
    }
}

#[derive(Debug, Clone)]
struct RegisteredClient {
    redirect_uris: Vec<String>,
    expires_at: Instant,
}

impl ClientRegistry {
    /// Production registry backed by the shared state DB, so registrations
    /// survive restarts (migration 0008 must have run — `state::connect` does).
    pub fn with_db(pool: PgPool) -> Self {
        Self {
            backend: Backend::Db(pool),
        }
    }

    /// Record a freshly registered client's redirect URIs (validated by the
    /// caller). Drops expired entries first; if still at the cap, rejects the
    /// new registration (`false`) rather than evicting a live client — an
    /// unauthenticated `/register` must never be able to knock out a legitimate
    /// client mid-flow. Returns `true` once recorded; updating an existing
    /// `client_id` always succeeds (it doesn't grow the store).
    ///
    /// A DB error fails **closed** (`false`, surfaced to the client as
    /// `temporarily_unavailable`): better to make the client retry than to
    /// pretend a registration `/authorize` can't then find was stored. Only a
    /// static message is logged, never the error — a `sqlx::Error` can embed the
    /// DSN (password) in its `Display` (see `state::connect`).
    pub async fn insert(&self, client_id: String, redirect_uris: Vec<String>) -> bool {
        match &self.backend {
            Backend::Db(pool) => Self::insert_db(pool, &client_id, &redirect_uris)
                .await
                .unwrap_or_else(|_| {
                    // Deliberately no error source: a `sqlx::Error` can render
                    // the DSN (password) in its `Display` (see `state::connect`).
                    tracing::warn!("client registration insert failed (state DB)");
                    false
                }),
            Backend::Memory(map) => {
                let mut map = map.lock().await;
                Self::gc_mem(&mut map);
                if map.len() >= CLIENT_CAP as usize && !map.contains_key(&client_id) {
                    return false;
                }
                map.insert(
                    client_id,
                    RegisteredClient {
                        redirect_uris,
                        expires_at: Instant::now() + CLIENT_TTL,
                    },
                );
                true
            }
        }
    }

    /// The registered redirect URIs for `client_id`, if the registration is
    /// still live. `None` means "unknown client" — `/authorize` rejects it. A DB
    /// error also yields `None` (fail closed: an unresolvable client is treated
    /// as unknown rather than waved through).
    pub async fn redirect_uris(&self, client_id: &str) -> Option<Vec<String>> {
        match &self.backend {
            Backend::Db(pool) => Self::lookup_db(pool, client_id).await.unwrap_or_else(|_| {
                // No error source — see the DSN-leak note on `insert`.
                tracing::warn!("client registration lookup failed (state DB)");
                None
            }),
            Backend::Memory(map) => {
                let mut map = map.lock().await;
                Self::gc_mem(&mut map);
                map.get(client_id).map(|c| c.redirect_uris.clone())
            }
        }
    }

    /// DB insert: GC lapsed rows, enforce the cap against live rows (rejecting a
    /// *new* client at the cap while still letting an existing one update), then
    /// upsert with a fresh TTL. The count/insert pair isn't one atomic step, but
    /// the cap is a best-effort ceiling on an unauthenticated endpoint, not an
    /// invariant — a transient one-over under a registration storm is harmless.
    async fn insert_db(
        pool: &PgPool,
        client_id: &str,
        redirect_uris: &[String],
    ) -> Result<bool, sqlx::Error> {
        sqlx::query("DELETE FROM oauth_clients WHERE expires_at <= now()")
            .execute(pool)
            .await?;

        // Only enforce the cap for a brand-new client; an existing `client_id`
        // updating its URIs doesn't grow the table, so let it through at cap.
        let exists: bool =
            sqlx::query_scalar("SELECT exists(SELECT 1 FROM oauth_clients WHERE client_id = $1)")
                .bind(client_id)
                .fetch_one(pool)
                .await?;
        if !exists {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
                .fetch_one(pool)
                .await?;
            if count >= CLIENT_CAP {
                return Ok(false);
            }
        }

        let uris = serde_json::to_value(redirect_uris).unwrap_or(serde_json::Value::Array(vec![]));
        let expires_at = Utc::now() + ChronoDuration::from_std(CLIENT_TTL).unwrap();
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, redirect_uris, expires_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (client_id) DO UPDATE \
               SET redirect_uris = EXCLUDED.redirect_uris, expires_at = EXCLUDED.expires_at",
        )
        .bind(client_id)
        .bind(&uris)
        .bind(expires_at)
        .execute(pool)
        .await?;
        Ok(true)
    }

    /// DB lookup: the live registration's URIs, or `None` if absent/expired.
    async fn lookup_db(pool: &PgPool, client_id: &str) -> Result<Option<Vec<String>>, sqlx::Error> {
        let row: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT redirect_uris FROM oauth_clients \
             WHERE client_id = $1 AND expires_at > now()",
        )
        .bind(client_id)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|v| serde_json::from_value(v).unwrap_or_default()))
    }

    fn gc_mem(map: &mut HashMap<String, RegisteredClient>) {
        let now = Instant::now();
        map.retain(|_, c| c.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_then_lookup_roundtrips() {
        let reg = ClientRegistry::default();
        assert!(reg.insert("c1".into(), vec!["https://app/cb".into()]).await);
        assert_eq!(
            reg.redirect_uris("c1").await,
            Some(vec!["https://app/cb".into()])
        );
        assert_eq!(reg.redirect_uris("unknown").await, None);
    }

    #[tokio::test]
    async fn at_cap_rejects_new_but_updates_existing() {
        let reg = ClientRegistry::default();
        let Backend::Memory(map) = &reg.backend else {
            unreachable!("default() is the memory backend");
        };
        {
            let mut map = map.lock().await;
            for i in 0..CLIENT_CAP {
                map.insert(
                    format!("c{i}"),
                    RegisteredClient {
                        redirect_uris: vec!["https://app/cb".into()],
                        expires_at: Instant::now() + CLIENT_TTL,
                    },
                );
            }
        }
        // At cap: a brand-new client is refused, no live client evicted.
        assert!(
            !reg.insert("overflow".into(), vec!["https://app/cb".into()])
                .await
        );
        assert_eq!(reg.redirect_uris("overflow").await, None);
        assert!(reg.redirect_uris("c0").await.is_some());
        // Updating an already-registered client still succeeds at cap.
        assert!(
            reg.insert("c0".into(), vec!["https://app/new".into()])
                .await
        );
        assert_eq!(
            reg.redirect_uris("c0").await,
            Some(vec!["https://app/new".into()])
        );
    }
}
