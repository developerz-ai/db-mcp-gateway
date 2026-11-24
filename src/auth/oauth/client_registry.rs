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

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::client_registry_mem::{RegisteredClient, insert_mem};
use super::{ClientName, StoreError};
use crate::state::oauth::{self as db, LiveClient};

/// Lifetime of a client a verified login has used (a code redeemed at
/// `/token`), sliding on every later one so an actively-used client never
/// lapses. Never granted by `/authorize` alone: it is unauthenticated, and a
/// row on this TTL is exempt from eviction at the cap.
///
/// 90 days because a client caches its `client_id` indefinitely and only
/// re-authorizes when its refresh chain runs out or the user signs out; a
/// shorter window GC'd the registration first and the browser landed on a bare
/// `invalid_client` page. `/authorize` self-heals the residual case (see
/// `oauth::authorize`).
const CLIENT_TTL: ChronoDuration = ChronoDuration::days(90);

/// Lifetime of a registration no login has used yet. A real client registers
/// and completes its login within minutes; an unauthenticated `/register` or
/// `/authorize` flood only ever produces rows like these, so they expire fast
/// and are the ones evicted at the cap.
pub(super) const UNAUTHORISED_CLIENT_TTL: ChronoDuration = ChronoDuration::hours(1);

/// Hard cap on registered clients. `/register` is unauthenticated (open DCR per
/// RFC 7591), so the store needs a ceiling. At the cap a registration evicts
/// the oldest expired or never-used row; a client a login has used is never
/// evicted, so a flood can't knock a legitimate client out. Only a store full
/// of used clients refuses ([`StoreError::StoreFull`]).
pub(super) const CLIENT_CAP: i64 = 10_000;

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

/// A live registration: what `/authorize` matches against and what the
/// consent page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    pub redirect_uris: Vec<String>,
    /// Self-asserted at `/register`, never verified. `None` for an adopted
    /// client or one registered without a name.
    pub client_name: Option<ClientName>,
}

impl ClientRegistry {
    /// Production registry backed by the shared state DB, so registrations
    /// survive restarts (migration 0008 must have run — `state::connect` does).
    pub fn with_db(pool: PgPool) -> Self {
        Self {
            backend: Backend::Db(pool),
        }
    }

    /// [`Self::register`] without a name.
    pub async fn insert(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
    ) -> Result<(), StoreError> {
        self.register(client_id, redirect_uris, None).await
    }

    /// Record a client's redirect URIs and name (validated by the caller) with
    /// the short never-used TTL. At the cap, evicts the oldest expired or
    /// never-used client first; `StoreFull` only when every row belongs to a
    /// used client. A DB error is `Backend` — fail closed, the client retries.
    /// Re-registering an existing `client_id` replaces its URIs and name (a
    /// lapsed, unswept one restarts as new) and needs the same room as a new
    /// one.
    pub async fn register(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
        client_name: Option<ClientName>,
    ) -> Result<(), StoreError> {
        let record = ClientRecord {
            redirect_uris,
            client_name,
        };
        match self.store(client_id, record, LiveClient::Replace).await? {
            true => Ok(()),
            false => Err(StoreError::StoreFull),
        }
    }

    /// Register a client `/authorize` adopted (unknown `client_id`, loopback
    /// redirect) and return the live registration. Adoption is as
    /// unauthenticated as `/register`, so the row starts on the never-used
    /// TTL, and a registration that is already live is returned untouched —
    /// the caller must match the redirect against what comes back.
    pub async fn adopt(
        &self,
        client_id: String,
        redirect_uri: String,
    ) -> Result<ClientRecord, StoreError> {
        let record = ClientRecord {
            redirect_uris: vec![redirect_uri],
            client_name: None,
        };
        self.store(client_id.clone(), record, LiveClient::Keep)
            .await?;
        // No row after the insert means the cap refused it.
        self.lookup(&client_id).await?.ok_or(StoreError::StoreFull)
    }

    /// `Ok(false)` when nothing was written: the cap refused the row, or
    /// `live` kept an existing registration.
    async fn store(
        &self,
        client_id: String,
        record: ClientRecord,
        live: LiveClient,
    ) -> Result<bool, StoreError> {
        match &self.backend {
            Backend::Db(pool) => db::insert_client_capped(
                pool,
                &client_id,
                &record.redirect_uris,
                record.client_name.as_ref().map(ClientName::as_str),
                CLIENT_CAP,
                UNAUTHORISED_CLIENT_TTL,
                live,
            )
            .await
            .map_err(|_| backend_error("insert")),
            Backend::Memory(map) => Ok(insert_mem(&mut *map.lock().await, client_id, record, live)),
        }
    }

    /// [`Self::lookup`]'s redirect URIs alone.
    pub async fn redirect_uris(&self, client_id: &str) -> Result<Option<Vec<String>>, StoreError> {
        Ok(self.lookup(client_id).await?.map(|c| c.redirect_uris))
    }

    /// The registration for `client_id`, if still live; `Ok(None)` means
    /// "unknown client". Read-only. A DB error is `Backend`, never `None`: an
    /// outage must not read as an unknown client the caller may then adopt.
    pub async fn lookup(&self, client_id: &str) -> Result<Option<ClientRecord>, StoreError> {
        match &self.backend {
            Backend::Db(pool) => db::find_client(pool, client_id)
                .await
                .map(|row| row.map(record_from_row))
                .map_err(|_| backend_error("lookup")),
            Backend::Memory(map) => {
                let map = map.lock().await;
                let live = map.get(client_id).filter(|c| c.expires_at > Utc::now());
                Ok(live.map(|c| c.record.clone()))
            }
        }
    }

    /// Slide a live client to a full [`CLIENT_TTL`], out of eviction range.
    /// Call only once a verified login has used the client. `Ok(false)` when
    /// the registration is gone.
    pub async fn promote(&self, client_id: &str) -> Result<bool, StoreError> {
        match &self.backend {
            Backend::Db(pool) => db::promote_client(pool, client_id, CLIENT_TTL)
                .await
                .map_err(|_| backend_error("promotion")),
            Backend::Memory(map) => {
                let mut map = map.lock().await;
                let now = Utc::now();
                let Some(client) = map.get_mut(client_id).filter(|c| c.expires_at > now) else {
                    return Ok(false);
                };
                client.expires_at = now + CLIENT_TTL;
                Ok(true)
            }
        }
    }

    /// Delete lapsed registrations; returns how many. Background GC task only
    /// — the request path never sweeps. A DB failure is logged and counts 0.
    pub async fn gc_expired(&self) -> u64 {
        match &self.backend {
            Backend::Db(pool) => db::delete_expired_clients(pool).await.unwrap_or_else(|_| {
                backend_error("GC");
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

/// Logs the failed operation and yields [`StoreError::Backend`]. Deliberately
/// drops the error source: a `sqlx::Error` can render the DSN (password) in
/// its `Display` (see `state::connect`).
fn backend_error(operation: &'static str) -> StoreError {
    tracing::warn!(operation, "client registry state-DB call failed");
    StoreError::Backend
}

/// A stored name that no longer parses (written outside `/register`) is shown
/// as no name rather than failing the lookup.
fn record_from_row(row: db::ClientRow) -> ClientRecord {
    let client_name = row
        .client_name
        .as_deref()
        .and_then(|raw| ClientName::parse(raw).ok().flatten());
    ClientRecord {
        redirect_uris: row.redirect_uris.0,
        client_name,
    }
}

#[cfg(test)]
#[path = "client_registry_tests.rs"]
mod tests;
