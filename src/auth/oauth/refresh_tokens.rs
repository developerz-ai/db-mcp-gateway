//! Rotating refresh tokens for the MCP OAuth bridge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::refresh_chain::{DEFAULT_REFRESH_TTL, chain_expired};
use super::{GrantIdentity, StoreError, hash_secret};
use crate::state::oauth::{self as db, NewRefreshToken};

/// Size cap on the refresh tokens map. This cap bounds resource exhaustion
/// from tokens belonging to many users or leaked tokens stored indefinitely.
const REFRESH_TOKENS_MAX_SIZE: usize = 100_000;

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
    backend: RefreshBackend,
    ttl: Duration,
}

#[derive(Clone)]
enum RefreshBackend {
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
        self.store(token, identity, Utc::now()).await
    }

    /// Insert a rotated token, carrying the chain's original `issued_at` forward
    /// so the absolute TTL is measured from the first mint, not this rotation.
    pub async fn insert_rotated(
        &self,
        token: &str,
        identity: GrantIdentity,
        issued_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.store(token, identity, issued_at).await
    }

    async fn store(
        &self,
        token: &str,
        identity: GrantIdentity,
        issued_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        match &self.backend {
            RefreshBackend::Db(pool) => {
                store_db(pool, hash_secret(token), &identity, issued_at, self.ttl)
                    .await
                    .map_err(|_| {
                        // Deliberately no error source: a `sqlx::Error` can render
                        // the DSN (password) in its `Display` (see `state::connect`).
                        tracing::warn!("refresh token insert failed (state DB)");
                        StoreError::Backend
                    })
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
                .map(|row| RefreshToken {
                    identity: GrantIdentity {
                        sub: row.user_sub,
                        email: row.email,
                        groups: serde_json::from_value(row.groups).unwrap_or_default(),
                    },
                    issued_at: row.chain_issued_at,
                })
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

    /// Remove all expired refresh token chains. Called periodically by a
    /// background task.
    pub async fn gc_expired(&self) {
        match &self.backend {
            RefreshBackend::Db(pool) => {
                if db::delete_expired_refresh_tokens(pool).await.is_err() {
                    // No error source — see the DSN-leak note on `store`.
                    tracing::warn!("refresh token GC failed (state DB)");
                }
            }
            RefreshBackend::Memory(map) => {
                let mut map = map.lock().await;
                let now = Utc::now();
                map.retain(|_, t| !chain_expired(t.issued_at, now, self.ttl));
            }
        }
    }
}

/// DB insert: enforce the cap against live rows (a rotation replaces its own
/// row, so it never grows the table and is let through at cap), then upsert.
/// The count/insert pair isn't atomic, but the cap is a resource ceiling, not
/// an invariant — a transient one-over is harmless.
async fn store_db(
    pool: &PgPool,
    token_hash: [u8; 32],
    identity: &GrantIdentity,
    issued_at: DateTime<Utc>,
    ttl: Duration,
) -> Result<(), sqlx::Error> {
    if !db::refresh_token_exists(pool, &token_hash).await?
        && db::count_refresh_tokens(pool).await? >= REFRESH_TOKENS_MAX_SIZE as i64
    {
        return Err(sqlx::Error::Protocol("refresh token store full".into()));
    }

    let groups =
        serde_json::to_value(&identity.groups).unwrap_or_else(|_| serde_json::Value::Array(vec![]));
    // `expires_at` materializes the absolute deadline so GC and the CHECK
    // constraint are plain comparisons. Infallible for any sane TTL; clamp
    // rather than panic (CLAUDE.md: no unwrap outside main/tests).
    let expires_at =
        issued_at + ChronoDuration::from_std(ttl).unwrap_or_else(|_| ChronoDuration::days(1));
    db::upsert_refresh_token(
        pool,
        &NewRefreshToken {
            token_hash: &token_hash,
            user_sub: &identity.sub,
            email: &identity.email,
            groups: &groups,
            chain_issued_at: issued_at,
            expires_at,
        },
    )
    .await
}

#[cfg(test)]
#[path = "refresh_tokens_tests.rs"]
mod tests;
