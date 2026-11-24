//! One-time authorization codes for the MCP OAuth bridge.
//!
//! Two backends behind one API, as for [`super::PendingFlows`]: the shared
//! state DB (`oauth_auth_codes`, migration 0022) in production, so `/token`
//! may land on any replica; an in-process map for tests.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::{GrantIdentity, StoreError, hash_secret};
use crate::state::oauth::{self as db, AuthCodeRow, NewAuthCode};

/// Cap on live authorization codes. Each code is one-time and redeemed
/// immediately; this cap bounds storage from unused/leaked codes.
const AUTH_CODES_MAX_SIZE: usize = 10_000;

/// TTL for a minted authorization code. Codes are one-time and redeemed
/// immediately by the client, so this is deliberately tight (OAuth 2.1
/// recommends ≤ 10 min; we use 1).
const CODE_TTL: Duration = Duration::seconds(60);

/// One-time authorization codes for the MCP OAuth bridge. A code maps to the
/// verified identity plus the PKCE challenge to verify at `/token`. The session
/// and tokens are minted only when the code is redeemed, so an abandoned login
/// leaves no orphan session.
#[derive(Clone)]
pub struct AuthCodes {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Db(PgPool),
    Memory(Arc<Mutex<HashMap<[u8; 32], AuthCode>>>),
}

impl Default for AuthCodes {
    fn default() -> Self {
        Self {
            backend: Backend::Memory(Arc::default()),
        }
    }
}

#[derive(Clone)]
pub struct AuthCode {
    /// Verified IdP identity to mint the session from at redemption.
    pub identity: GrantIdentity,
    /// PKCE S256 challenge the redeeming `code_verifier` must satisfy.
    pub code_challenge: String,
    /// Redirect URI from `/authorize`; `/token` must present the same value.
    pub redirect_uri: String,
    /// Registered client_id from `/authorize`; `/token` verifies the presenter
    /// matches the registrant (OAuth 2.1 §4.1.3 for public clients).
    pub client_id: String,
    expires_at: DateTime<Utc>,
}

impl From<AuthCodeRow> for AuthCode {
    fn from(row: AuthCodeRow) -> Self {
        Self {
            identity: GrantIdentity {
                sub: row.user_sub,
                email: row.email,
                groups: row.groups.0,
            },
            code_challenge: row.code_challenge,
            redirect_uri: row.redirect_uri,
            client_id: row.client_id,
            expires_at: row.expires_at,
        }
    }
}

impl AuthCode {
    fn row<'a>(&'a self, code_hash: &'a [u8; 32]) -> NewAuthCode<'a> {
        NewAuthCode {
            code_hash,
            user_sub: &self.identity.sub,
            email: &self.identity.email,
            groups: &self.identity.groups,
            code_challenge: &self.code_challenge,
            redirect_uri: &self.redirect_uri,
            client_id: &self.client_id,
        }
    }
}

impl AuthCodes {
    /// Production store in the shared state DB (migration 0022 must have run
    /// — `state::connect` does).
    pub fn with_db(pool: PgPool) -> Self {
        Self {
            backend: Backend::Db(pool),
        }
    }

    pub async fn insert(
        &self,
        code: &str,
        identity: GrantIdentity,
        code_challenge: String,
        redirect_uri: String,
        client_id: String,
    ) -> Result<(), StoreError> {
        let code_hash = hash_secret(code);
        let entry = AuthCode {
            identity,
            code_challenge,
            redirect_uri,
            client_id,
            expires_at: Utc::now() + CODE_TTL,
        };
        let inserted = match &self.backend {
            Backend::Db(pool) => db::insert_auth_code_capped(
                pool,
                &entry.row(&code_hash),
                CODE_TTL,
                AUTH_CODES_MAX_SIZE as i64,
            )
            .await
            .map_err(|_| backend_error("insert"))?,
            Backend::Memory(map) => insert_mem(&mut *map.lock().await, code_hash, entry),
        };
        if inserted {
            Ok(())
        } else {
            Err(StoreError::StoreFull)
        }
    }

    /// Remove and return a live code (one-time use). Of two concurrent takes
    /// of one code, at most one gets it.
    pub async fn take(&self, code: &str) -> Result<Option<AuthCode>, StoreError> {
        let code_hash = hash_secret(code);
        match &self.backend {
            Backend::Db(pool) => db::take_auth_code(pool, &code_hash)
                .await
                .map(|row| row.map(AuthCode::from))
                .map_err(|_| backend_error("take")),
            Backend::Memory(map) => {
                let taken = map.lock().await.remove(&code_hash);
                Ok(taken.filter(|code| code.expires_at > Utc::now()))
            }
        }
    }

    /// Put back a code [`Self::take`] removed, with its original deadline.
    /// Only for a redemption that failed on the gateway's side provably before
    /// anything was issued: the client is told to retry, so the retry must
    /// find the code. Never after a mint whose COMMIT was sent. `Err` means the
    /// code is gone for good: the caller must not tell the client to retry.
    /// The cap applies as on insert: the take freed the code's slot, and a
    /// new code may have taken it since.
    pub async fn restore(&self, code: &str, entry: AuthCode) -> Result<(), StoreError> {
        let code_hash = hash_secret(code);
        let restored = match &self.backend {
            Backend::Db(pool) => db::restore_auth_code(
                pool,
                &entry.row(&code_hash),
                entry.expires_at,
                AUTH_CODES_MAX_SIZE as i64,
            )
            .await
            .map_err(|_| backend_error("restore"))?,
            Backend::Memory(map) => insert_mem(&mut *map.lock().await, code_hash, entry),
        };
        if restored {
            Ok(())
        } else {
            Err(StoreError::StoreFull)
        }
    }

    /// Remove all expired codes; returns how many. Called periodically by the
    /// auth GC loop; logs its own DB failure.
    pub async fn gc_expired(&self) -> u64 {
        match &self.backend {
            Backend::Db(pool) => db::delete_expired_auth_codes(pool)
                .await
                .unwrap_or_else(|_| {
                    backend_error("GC");
                    0
                }),
            Backend::Memory(map) => {
                let mut map = map.lock().await;
                let now = Utc::now();
                let before = map.len();
                map.retain(|_, code| code.expires_at > now);
                (before - map.len()) as u64
            }
        }
    }
}

/// Memory twin of `db::insert_auth_code_capped`: lapsed codes do not count
/// against the cap, so a burst that has since expired never wedges logins.
fn insert_mem(map: &mut HashMap<[u8; 32], AuthCode>, code_hash: [u8; 32], entry: AuthCode) -> bool {
    if map.len() >= AUTH_CODES_MAX_SIZE {
        let now = Utc::now();
        map.retain(|_, code| code.expires_at > now);
    }
    if map.len() >= AUTH_CODES_MAX_SIZE {
        return false;
    }
    map.insert(code_hash, entry);
    true
}

/// Logs the failed operation and yields [`StoreError::Backend`]. Deliberately
/// drops the error source: a `sqlx::Error` can render the DSN.
fn backend_error(operation: &'static str) -> StoreError {
    tracing::warn!(operation, "authorization code state-DB call failed");
    StoreError::Backend
}

#[cfg(test)]
#[path = "auth_codes_tests.rs"]
mod tests;
