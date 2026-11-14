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
//! - **Memory** (`default`) — unit tests and test harnesses without a state DB.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::StoreError;
use crate::state::oauth as db;

/// Lifetime of a client that has completed a successful `/authorize`, sliding
/// on every later one so an actively-used client never lapses.
///
/// 90 days because a client caches its `client_id` indefinitely and only
/// re-authorizes when its refresh chain runs out or the user signs out; a
/// shorter window GC'd the registration first and the browser landed on a bare
/// `invalid_client` page. `/authorize` self-heals the residual case (see
/// `oauth::authorize`).
const CLIENT_TTL: ChronoDuration = ChronoDuration::days(90);

/// Lifetime of a registration no `/authorize` has used yet. A real client
/// registers and authorizes within seconds; an unauthenticated `/register`
/// flood only ever produces rows like these, so they expire fast and are the
/// ones evicted at the cap.
const UNAUTHORISED_CLIENT_TTL: ChronoDuration = ChronoDuration::hours(1);

/// Hard cap on registered clients. `/register` is unauthenticated (open DCR per
/// RFC 7591), so the store needs a ceiling. At the cap a registration evicts
/// the oldest expired or never-authorised row; a client that has authorized is
/// never evicted, so a flood can't knock a legitimate client out. Only a store
/// full of authorised clients refuses ([`StoreError::StoreFull`]).
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
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl RegisteredClient {
    fn evictable(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now || self.expires_at <= self.created_at + UNAUTHORISED_CLIENT_TTL
    }
}

impl ClientRegistry {
    /// Production registry backed by the shared state DB, so registrations
    /// survive restarts (migration 0008 must have run — `state::connect` does).
    pub fn with_db(pool: PgPool) -> Self {
        Self {
            backend: Backend::Db(pool),
        }
    }

    /// Record a client's redirect URIs (validated by the caller) with the
    /// short never-authorised TTL. At the cap, evicts the oldest expired or
    /// never-authorised client first; `StoreFull` only when every row belongs
    /// to an authorised client. A DB error is `Backend` — fail closed, the
    /// client retries. Re-registering an existing `client_id` replaces its URIs
    /// (a lapsed, unswept one restarts as new) and needs the same room as a new
    /// one.
    pub async fn insert(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
    ) -> Result<(), StoreError> {
        let stored = match &self.backend {
            Backend::Db(pool) => db::insert_client_capped(
                pool,
                &client_id,
                &redirect_uris,
                CLIENT_CAP,
                UNAUTHORISED_CLIENT_TTL,
            )
            .await
            .map_err(|_| {
                // Deliberately no error source: a `sqlx::Error` can render the
                // DSN (password) in its `Display` (see `state::connect`).
                tracing::warn!("client registration insert failed (state DB)");
                StoreError::Backend
            })?,
            Backend::Memory(map) => insert_mem(&mut *map.lock().await, client_id, redirect_uris),
        };
        if stored {
            Ok(())
        } else {
            Err(StoreError::StoreFull)
        }
    }

    /// Register a client `/authorize` adopted (unknown `client_id`, loopback
    /// redirect) — the authorize itself is its first use, so it is promoted
    /// to [`CLIENT_TTL`] at once instead of expiring as never-authorised.
    pub async fn adopt(&self, client_id: String, redirect_uri: String) -> Result<(), StoreError> {
        self.insert(client_id.clone(), vec![redirect_uri]).await?;
        match self.redirect_uris(&client_id).await {
            Some(_) => Ok(()),
            None => Err(StoreError::Backend),
        }
    }

    /// The registered redirect URIs for `client_id`, if the registration is
    /// still live; `None` means "unknown client". A DB error also yields `None`
    /// (fail closed). A hit slides `expires_at` to a full [`CLIENT_TTL`] — the
    /// first one promotes a never-authorised client out of eviction range.
    pub async fn redirect_uris(&self, client_id: &str) -> Option<Vec<String>> {
        match &self.backend {
            Backend::Db(pool) => db::touch_client(pool, client_id, CLIENT_TTL)
                .await
                .unwrap_or_else(|_| {
                    // No error source — see the DSN-leak note on `insert`.
                    tracing::warn!("client registration lookup failed (state DB)");
                    None
                }),
            Backend::Memory(map) => {
                let mut map = map.lock().await;
                let now = Utc::now();
                let client = map.get_mut(client_id).filter(|c| c.expires_at > now)?;
                client.expires_at = now + CLIENT_TTL;
                Some(client.redirect_uris.clone())
            }
        }
    }

    /// Delete lapsed registrations; returns how many. Background GC task only
    /// — the request path never sweeps. A DB failure is logged and counts 0.
    pub async fn gc_expired(&self) -> u64 {
        match &self.backend {
            Backend::Db(pool) => db::delete_expired_clients(pool).await.unwrap_or_else(|_| {
                // No error source — see the DSN-leak note on `insert`.
                tracing::warn!("client registration GC failed (state DB)");
                0
            }),
            Backend::Memory(map) => {
                let now = Utc::now();
                let mut map = map.lock().await;
                let before = map.len();
                map.retain(|_, c| c.expires_at > now);
                (before - map.len()) as u64
            }
        }
    }
}

/// Memory twin of `db::insert_client_capped`. `false` when the map is full of
/// authorised clients.
fn insert_mem(
    map: &mut HashMap<String, RegisteredClient>,
    client_id: String,
    redirect_uris: Vec<String>,
) -> bool {
    let now = Utc::now();
    if map.len() >= CLIENT_CAP as usize {
        let oldest = map
            .iter()
            .filter(|(_, c)| c.evictable(now))
            .min_by_key(|(_, c)| c.created_at)
            .map(|(id, _)| id.clone());
        let Some(oldest) = oldest else {
            return false;
        };
        map.remove(&oldest);
    }
    match map.get_mut(&client_id) {
        Some(existing) if existing.expires_at > now => existing.redirect_uris = redirect_uris,
        // Absent, or lapsed but not yet GC'd: (re)start as never-authorised.
        _ => {
            map.insert(
                client_id,
                RegisteredClient {
                    redirect_uris,
                    created_at: now,
                    expires_at: now + UNAUTHORISED_CLIENT_TTL,
                },
            );
        }
    }
    true
}

#[cfg(test)]
#[path = "client_registry_tests.rs"]
mod tests;
