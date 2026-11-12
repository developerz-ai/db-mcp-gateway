//! Auth state for the round-trips the OAuth bridge fronts in `transport/oauth/`.
//!
//! Three TTL-bounded stores plus the context they carry: pending IdP logins
//! ([`PendingFlows`]), one-time authorization codes ([`AuthCodes`]), and
//! rotating refresh tokens ([`RefreshTokens`]); plus the
//! Dynamic-Client-Registration store ([`ClientRegistry`]) and the
//! [`AuthFacade`] that bundles them for the HTTP handlers.
//!
//! The first two are in-process by design — both are seconds-to-minutes legs of
//! a single browser round-trip, so a restart mid-login is a retry, not a
//! sign-out. An HA deployment must still pin the OAuth dance to one replica or
//! sticky-route it (see `website/docs/initial-idea/02-architecture.md#ha`).
//!
//! [`RefreshTokens`] and [`ClientRegistry`] are the exception: both are meant to
//! outlive the process, so production persists them in the state DB
//! (`crate::state::oauth`).

mod auth_codes;
mod client_registry;
mod facade;
mod grants;
mod pending_flows;
mod refresh_chain;
mod refresh_db;
mod refresh_tokens;

use sha2::{Digest, Sha256};

pub use auth_codes::{AuthCode, AuthCodes};
pub use client_registry::ClientRegistry;
pub use facade::{AuthFacade, IssuedTokens};
pub use grants::Minted;
pub use pending_flows::{OAuthBridge, PendingFlow, PendingFlows};
pub use refresh_chain::DEFAULT_REFRESH_TTL;
pub use refresh_tokens::{RefreshToken, RefreshTokens};

/// Error type for store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The store has reached its size cap; new entries are rejected.
    #[error("auth store full")]
    StoreFull,
    /// The backing store (state DB) is unreachable or rejected the write. Never
    /// carries the underlying `sqlx::Error` — its `Display` can embed the DSN.
    #[error("auth store unavailable")]
    Backend,
}

/// The verified IdP identity carried by a pending auth code or refresh token —
/// enough to mint a fresh gateway session at redemption time.
#[derive(Debug, Clone)]
pub struct GrantIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// Hash a bearer secret (authorization code or refresh token) for at-rest
/// storage. The store is keyed by this digest, never the raw secret, so a memory
/// dump or a stray `Debug` of the map can't be replayed as a live token; lookups
/// hash the presented value and match digests. SHA-256 is preimage-resistant, so
/// the stored digest can't be turned back into a usable token.
fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_secret_is_not_the_raw_input_and_is_deterministic() {
        let h = hash_secret("super-secret-token");
        assert_ne!(h.as_slice(), b"super-secret-token");
        assert_eq!(h, hash_secret("super-secret-token"));
        assert_ne!(hash_secret("a"), hash_secret("b"));
    }
}
