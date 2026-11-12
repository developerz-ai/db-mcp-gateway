//! One-time authorization codes for the MCP OAuth bridge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::{GrantIdentity, StoreError, hash_secret};

/// Size cap on the authorization codes map. Each code is one-time and
/// redeemed immediately; this cap bounds memory from unused/leaked codes.
const AUTH_CODES_MAX_SIZE: usize = 10_000;

/// TTL for a minted authorization code. Codes are one-time and redeemed
/// immediately by the client, so this is deliberately tight (OAuth 2.1
/// recommends ≤ 10 min; we use 1).
const CODE_TTL: Duration = Duration::from_secs(60);

/// One-time authorization codes for the MCP OAuth bridge. A code maps to the
/// verified identity plus the PKCE challenge to verify at `/token`. The session
/// and tokens are minted only when the code is redeemed, so an abandoned login
/// leaves no orphan session.
#[derive(Clone, Default, Debug)]
pub struct AuthCodes {
    inner: Arc<Mutex<HashMap<[u8; 32], AuthCode>>>,
}

#[derive(Debug, Clone)]
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
    expires_at: Instant,
}

impl AuthCodes {
    pub async fn insert(
        &self,
        code: &str,
        identity: GrantIdentity,
        code_challenge: String,
        redirect_uri: String,
        client_id: String,
    ) -> Result<(), StoreError> {
        let mut map = self.inner.lock().await;
        // Same opportunistic-GC-before-reject as `PendingFlows::insert_flow`
        // — reclaim already-expired codes before giving up, so a burst that
        // filled the map with codes that have since redeemed-or-expired
        // doesn't wedge new logins for the rest of the periodic sweep
        // interval.
        if map.len() >= AUTH_CODES_MAX_SIZE {
            let now = Instant::now();
            map.retain(|_, ac| ac.expires_at > now);
        }
        if map.len() >= AUTH_CODES_MAX_SIZE {
            return Err(StoreError::StoreFull);
        }
        map.insert(
            hash_secret(code),
            AuthCode {
                identity,
                code_challenge,
                redirect_uri,
                client_id,
                expires_at: Instant::now() + CODE_TTL,
            },
        );
        Ok(())
    }

    /// Remove and return a code (one-time use), if still live (i.e., not yet
    /// expired past the code TTL).
    pub async fn take(&self, code: &str) -> Option<AuthCode> {
        let mut map = self.inner.lock().await;
        if let Some(ac) = map.remove(&hash_secret(code)) {
            // Check expiration before returning: if the code has passed its TTL,
            // reject it (treat as if it doesn't exist). The background GC task
            // will clean up the rest.
            if ac.expires_at > Instant::now() {
                Some(ac)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Remove all expired codes. Called periodically by a background task.
    pub async fn gc_expired(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, code| code.expires_at > now);
    }
}

#[cfg(test)]
#[path = "auth_codes_tests.rs"]
mod tests;
