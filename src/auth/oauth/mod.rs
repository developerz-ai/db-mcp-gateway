//! Auth state for the round-trips the OAuth bridge fronts in `transport/oauth/`.
//!
//! Three TTL-bounded stores plus the context they carry: pending IdP logins
//! ([`PendingFlows`]), one-time authorization codes ([`AuthCodes`]), and
//! rotating refresh tokens ([`RefreshTokens`]); plus the
//! Dynamic-Client-Registration store ([`ClientRegistry`]) and the
//! [`AuthFacade`] that bundles them for the HTTP handlers.
//!
//! Production persists every one of them in the shared state DB
//! (`crate::state::oauth`), so each leg of a login may land on any replica — no
//! sticky routing (`website/docs/initial-idea/02-architecture.md#ha`). Each
//! store also has an in-process backend for tests.

mod auth_codes;
mod client_name;
mod client_registry;
mod client_registry_mem;
mod facade;
mod grants;
mod login_secrets;
mod pending_flows;
mod pending_flows_db;
mod pending_flows_mem;
mod redaction;
mod refresh_chain;
mod refresh_db;
mod refresh_tokens;
mod rotation;

use sha2::{Digest, Sha256};

pub use auth_codes::{AuthCode, AuthCodes};
pub use client_name::{ClientName, InvalidClientName, MAX_CLIENT_NAME_CHARS};
pub use client_registry::{ClientRecord, ClientRegistry};
pub use facade::{AuthFacade, IssuedTokens, Refreshed};
pub use grants::{MintError, Minted};
pub use login_secrets::LoginSecrets;
pub use pending_flows::{OAuthBridge, PendingConsent, PendingFlow, PendingFlows};
pub use refresh_chain::DEFAULT_REFRESH_TTL;
pub use refresh_tokens::{RefreshToken, RefreshTokens};
pub use rotation::Rotation;

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
#[derive(Clone)]
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
