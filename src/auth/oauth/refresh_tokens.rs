//! Rotating refresh tokens for the MCP OAuth bridge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::refresh_chain::{DEFAULT_REFRESH_TTL, chain_expired};
use super::refresh_db::{NewDbToken, REFRESH_TOKENS_MAX_SIZE, store_db};
use super::{GrantIdentity, StoreError, hash_secret};
use crate::auth::SessionId;
use crate::state::oauth::{self as db, RefreshTokenRow};

/// Refresh-token store: hashed token → the verified identity it renews. Rotated
/// on every redemption (the old token is removed, a new one issued), per OAuth
/// 2.1 §4.3.1 for public clients.
///
/// Two backends behind one API, mirroring [`super::ClientRegistry`]:
/// - **DB** (`with_db`) — the production path. Chains live in the shared state
///   DB (`oauth_refresh_tokens`, migration 0009). In memory, a redeploy dropped
///   every chain and forced every signed-in agent through a full browser SSO
///   login, which made `REFRESH_TTL_DAYS` a fiction — the real "stay signed in"
///   ceiling was time-until-next-rollout, not the configured window.
/// - **Memory** (`default`) — unit tests and the auth-less test bootstrap.
///
/// `ttl` is the absolute chain lifetime (see [`DEFAULT_REFRESH_TTL`]); production
/// threads the configured `AuthConfig::refresh_ttl` via [`RefreshTokens::with_db`].
#[derive(Clone)]
pub struct RefreshTokens {
    pub(super) backend: RefreshBackend,
    ttl: Duration,
}

#[derive(Clone)]
pub(super) enum RefreshBackend {
    Db(PgPool),
    Memory(Arc<Mutex<HashMap<[u8; 32], RefreshToken>>>),
}

impl std::fmt::Debug for RefreshTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-rolled: `PgPool`'s Debug can render the DSN (password). Never let
        // it reach a log line — same guard as `ClientRegistry` / `SessionStore`.
        let backend = match &self.backend {
            RefreshBackend::Db(_) => "Db(<PgPool>)",
            RefreshBackend::Memory(_) => "Memory",
        };
        f.debug_struct("RefreshTokens")
            .field("backend", &backend)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl Default for RefreshTokens {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_REFRESH_TTL)
    }
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub identity: GrantIdentity,
    /// When the rotation *chain* this token belongs to was first minted. Carried
    /// verbatim across rotations (see [`RefreshTokens::insert_rotated`]) so the
    /// chain expires an absolute TTL after the first token — rotation renews the
    /// opaque value but never the deadline.
    pub issued_at: DateTime<Utc>,
    /// The access session minted alongside this token; rotation and `/revoke`
    /// revoke it. `None` for rows written before migration 0012.
    pub session_id: Option<SessionId>,
}

impl From<RefreshTokenRow> for RefreshToken {
    fn from(row: RefreshTokenRow) -> Self {
        Self {
            identity: GrantIdentity {
                sub: row.user_sub,
                email: row.email,
                groups: row.groups.0,
            },
            issued_at: row.chain_issued_at,
            session_id: row.session_id.map(SessionId::from),
        }
    }
}

impl RefreshTokens {
    /// Production store: chains persisted in the shared state DB, so a restart
    /// or redeploy no longer signs every agent out (migration 0009 must have run
    /// — `state::connect` does). `ttl` is `AuthConfig::refresh_ttl`.
    pub fn with_db(pool: PgPool, ttl: Duration) -> Self {
        Self {
            backend: RefreshBackend::Db(pool),
            ttl,
        }
    }

    /// In-memory store with a caller-chosen absolute chain TTL. Tests only —
    /// production uses [`RefreshTokens::with_db`].
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            backend: RefreshBackend::Memory(Arc::default()),
            ttl,
        }
    }

    /// The absolute chain lifetime this store enforces.
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Insert a token that starts a fresh chain (birth = now). Used when the
    /// token is minted off an authorization-code redemption, not a rotation.
    pub async fn insert(&self, token: &str, identity: GrantIdentity) -> Result<(), StoreError> {
        self.store(token, identity, Utc::now(), None).await
    }

    /// Insert a rotated token, carrying the chain's original `issued_at` forward
    /// so the absolute TTL is measured from the first mint, not this rotation.
    pub async fn insert_rotated(
        &self,
        token: &str,
        identity: GrantIdentity,
        issued_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.store(token, identity, issued_at, None).await
    }

    pub(super) async fn store(
        &self,
        token: &str,
        identity: GrantIdentity,
        issued_at: DateTime<Utc>,
        session_id: Option<SessionId>,
    ) -> Result<(), StoreError> {
        match &self.backend {
            RefreshBackend::Db(pool) => {
                let mut conn = pool.acquire().await.map_err(|_| StoreError::Backend)?;
                let new = NewDbToken {
                    token_hash: hash_secret(token),
                    identity: &identity,
                    issued_at,
                    session_id,
                };
                match store_db(&mut conn, &new, self.ttl).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(StoreError::StoreFull),
                    Err(_) => {
                        // Deliberately no error source: a `sqlx::Error` can render
                        // the DSN (password) in its `Display` (see `state::connect`).
                        tracing::warn!("refresh token insert failed (state DB)");
                        Err(StoreError::Backend)
                    }
                }
            }
            RefreshBackend::Memory(map) => {
                let mut map = map.lock().await;
                let key = hash_secret(token);
                // Check size before inserting; reject if full. Replacing an
                // existing key doesn't grow the map, so let it through at cap.
                if map.len() >= REFRESH_TOKENS_MAX_SIZE && !map.contains_key(&key) {
                    return Err(StoreError::StoreFull);
                }
                map.insert(
                    key,
                    RefreshToken {
                        identity,
                        issued_at,
                        session_id,
                    },
                );
                Ok(())
            }
        }
    }

    /// Remove and return a refresh token (rotation consumes it), if still live
    /// (i.e., not yet expired past the absolute chain TTL).
    ///
    /// A DB error yields `None` — fail closed: an unresolvable token is treated
    /// as invalid rather than waved through.
    pub async fn take(&self, token: &str) -> Option<RefreshToken> {
        match &self.backend {
            RefreshBackend::Db(pool) => db::take_refresh_token(pool, &hash_secret(token))
                .await
                .unwrap_or_else(|_| {
                    // No error source — see the DSN-leak note on `store`.
                    tracing::warn!("refresh token lookup failed (state DB)");
                    None
                })
                .map(RefreshToken::from)
                // The row's own `expires_at` already gates redemption, but
                // re-check against the *current* configured TTL so lowering
                // `REFRESH_TTL_DAYS` takes effect on chains minted under the
                // old, longer window instead of honoring the stale deadline.
                .filter(|rt| !chain_expired(rt.issued_at, Utc::now(), self.ttl)),
            RefreshBackend::Memory(map) => {
                let mut map = map.lock().await;
                let rt = map.remove(&hash_secret(token))?;
                // Check expiration before returning: if the chain has passed its
                // absolute TTL, reject it (treat as if it doesn't exist). The
                // background GC task will clean up the rest.
                (!chain_expired(rt.issued_at, Utc::now(), self.ttl)).then_some(rt)
            }
        }
    }

    /// Drop every refresh token belonging to `sub`, returning how many were
    /// removed. Logout calls this: revoking the session row alone leaves this
    /// identity's refresh chains live, so a logged-out user could silently mint a
    /// fresh session via the refresh grant. A chain carries no stable session id
    /// (each rotation mints a new session), so `sub` is the only handle spanning
    /// it — hence purge-by-identity rather than per-token. (O4)
    pub async fn purge_for_sub(&self, sub: &str) -> usize {
        match &self.backend {
            RefreshBackend::Db(pool) => db::delete_refresh_tokens_for_sub(pool, sub)
                .await
                .map(|n| n as usize)
                .unwrap_or_else(|_| {
                    // No error source — see the DSN-leak note on `store`.
                    // Logout still revokes the session row; surface the
                    // failed purge as 0 rather than a bogus count.
                    tracing::warn!("refresh token purge failed (state DB)");
                    0
                }),
            RefreshBackend::Memory(map) => {
                let mut map = map.lock().await;
                let before = map.len();
                map.retain(|_, t| t.identity.sub != sub);
                before - map.len()
            }
        }
    }

    /// Remove all expired refresh token chains; returns how many. Called
    /// periodically by a background task. A DB failure is logged and counts 0.
    pub async fn gc_expired(&self) -> u64 {
        match &self.backend {
            RefreshBackend::Db(pool) => db::delete_expired_refresh_tokens(pool)
                .await
                .unwrap_or_else(|_| {
                    // No error source — see the DSN-leak note on `store`.
                    tracing::warn!("refresh token GC failed (state DB)");
                    0
                }),
            RefreshBackend::Memory(map) => {
                let mut map = map.lock().await;
                let now = Utc::now();
                let before = map.len();
                map.retain(|_, t| !chain_expired(t.issued_at, now, self.ttl));
                (before - map.len()) as u64
            }
        }
    }
}

#[cfg(test)]
#[path = "refresh_tokens_tests.rs"]
mod tests;
