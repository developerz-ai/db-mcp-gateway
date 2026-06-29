//! In-memory flow state for the auth round-trips fronted by `transport/`.
//!
//! Three TTL-bounded stores plus the context they carry: pending IdP logins
//! ([`PendingFlows`]), one-time authorization codes ([`AuthCodes`]), and
//! rotating refresh tokens ([`RefreshTokens`]). All are in-process — a restart
//! drops them and an HA deployment must pin the OAuth dance to one replica or
//! sticky-route it (see `docs/initial-idea/02-architecture.md#ha`). The
//! Dynamic-Client-Registration store lives next door in
//! [`super::client_registry`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

/// Hash a bearer secret (authorization code or refresh token) for at-rest
/// storage. The store is keyed by this digest, never the raw secret, so a memory
/// dump or a stray `Debug` of the map can't be replayed as a live token; lookups
/// hash the presented value and match digests. SHA-256 is preimage-resistant, so
/// the stored digest can't be turned back into a usable token.
fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// `state → nonce` from /auth/login lives here until /auth/callback consumes
/// (and removes) it. TTL-bounded so a wedged login can't accumulate.
const FLOW_TTL: Duration = Duration::from_secs(5 * 60);

/// Context an MCP OAuth-bridge `/authorize` request stashes across the IdP
/// round-trip. Recovered at `/auth/callback` (keyed by the OIDC `state`) so the
/// gateway can mint an authorization code and 302 back to the *client's* own
/// redirect URI — the loopback Claude Code listens on.
#[derive(Debug, Clone)]
pub struct OAuthBridge {
    /// The client_id from `/register` — carried through so `/token` can verify
    /// the presenter matches the registrant.
    pub client_id: String,
    /// The MCP client's registered redirect URI (loopback or https).
    pub client_redirect_uri: String,
    /// The MCP client's `state` — echoed back verbatim on the final redirect.
    pub client_state: String,
    /// PKCE challenge (S256). Verified against `code_verifier` at `/token`.
    pub code_challenge: String,
    /// RFC 8707 `resource` the client bound the request to (audit/diagnostics).
    pub resource: Option<String>,
}

#[derive(Clone, Default, Debug)]
pub struct PendingFlows {
    inner: Arc<Mutex<HashMap<String, PendingFlow>>>,
}

#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub nonce: String,
    /// PKCE `code_verifier` the gateway (as an OAuth *client*) sends to the
    /// upstream IdP at the token exchange — distinct from any client-facing
    /// PKCE in `bridge`.
    pub idp_verifier: String,
    /// `Some` for an MCP OAuth-bridge login; `None` for the bespoke
    /// `/auth/login` flow that returns the session token as JSON.
    pub bridge: Option<OAuthBridge>,
    expires_at: Instant,
}

impl PendingFlows {
    pub async fn insert(&self, state: String, nonce: String, idp_verifier: String) {
        self.insert_flow(state, nonce, idp_verifier, None).await;
    }

    /// Insert a flow carrying MCP OAuth-bridge context (the client redirect /
    /// state / PKCE challenge to honor once the IdP round-trip completes).
    pub async fn insert_bridge(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: OAuthBridge,
    ) {
        self.insert_flow(state, nonce, idp_verifier, Some(bridge))
            .await;
    }

    async fn insert_flow(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: Option<OAuthBridge>,
    ) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            state,
            PendingFlow {
                nonce,
                idp_verifier,
                bridge,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
    }

    /// Remove and return the pending flow for a given state, if still live.
    pub async fn take(&self, state: &str) -> Option<PendingFlow> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(state)
    }

    fn gc(map: &mut HashMap<String, PendingFlow>) {
        let now = Instant::now();
        map.retain(|_, flow| flow.expires_at > now);
    }
}

/// TTL for a minted authorization code. Codes are one-time and redeemed
/// immediately by the client, so this is deliberately tight (OAuth 2.1
/// recommends ≤ 10 min; we use 1).
const CODE_TTL: Duration = Duration::from_secs(60);

/// The verified IdP identity carried by a pending auth code or refresh token —
/// enough to mint a fresh gateway session at redemption time.
#[derive(Debug, Clone)]
pub struct GrantIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

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
    ) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
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
    }

    /// Remove and return a code (one-time use), if still live.
    pub async fn take(&self, code: &str) -> Option<AuthCode> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(&hash_secret(code))
    }

    fn gc(map: &mut HashMap<[u8; 32], AuthCode>) {
        let now = Instant::now();
        map.retain(|_, code| code.expires_at > now);
    }
}

/// Absolute lifetime of a refresh-token *chain*, measured from the first token's
/// mint and **never extended by rotation**. Long enough that a developer rarely
/// re-does the browser login, short enough to bound a leaked (and silently
/// rotated) chain's usefulness — without this cap, a continuously rotated chain
/// would live forever.
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Refresh-token store: hashed token → the verified identity it renews. Rotated
/// on every redemption (the old token is removed, a new one issued), per OAuth
/// 2.1 §4.3.1 for public clients. In-memory like the other flow state — see the
/// deployment note on single-replica / sticky routing for the auth dance.
#[derive(Clone, Default, Debug)]
pub struct RefreshTokens {
    inner: Arc<Mutex<HashMap<[u8; 32], RefreshToken>>>,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub identity: GrantIdentity,
    /// When the rotation *chain* this token belongs to was first minted. Carried
    /// verbatim across rotations (see [`RefreshTokens::insert_rotated`]) so the
    /// chain expires an absolute [`REFRESH_TTL`] after the first token — rotation
    /// renews the opaque value but never the deadline.
    pub issued_at: Instant,
}

impl RefreshTokens {
    /// Insert a token that starts a fresh chain (birth = now). Used when the
    /// token is minted off an authorization-code redemption, not a rotation.
    pub async fn insert(&self, token: &str, identity: GrantIdentity) {
        self.store(token, identity, Instant::now()).await;
    }

    /// Insert a rotated token, carrying the chain's original `issued_at` forward
    /// so the absolute TTL is measured from the first mint, not this rotation.
    pub async fn insert_rotated(&self, token: &str, identity: GrantIdentity, issued_at: Instant) {
        self.store(token, identity, issued_at).await;
    }

    async fn store(&self, token: &str, identity: GrantIdentity, issued_at: Instant) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            hash_secret(token),
            RefreshToken {
                identity,
                issued_at,
            },
        );
    }

    /// Remove and return a refresh token (rotation consumes it), if still live.
    pub async fn take(&self, token: &str) -> Option<RefreshToken> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(&hash_secret(token))
    }

    fn gc(map: &mut HashMap<[u8; 32], RefreshToken>) {
        let now = Instant::now();
        map.retain(|_, t| t.issued_at + REFRESH_TTL > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> GrantIdentity {
        GrantIdentity {
            sub: "u1".into(),
            email: "u1@example.com".into(),
            groups: vec!["eng".into()],
        }
    }

    #[test]
    fn hash_secret_is_not_the_raw_input_and_is_deterministic() {
        let h = hash_secret("super-secret-token");
        assert_ne!(h.as_slice(), b"super-secret-token");
        assert_eq!(h, hash_secret("super-secret-token"));
        assert_ne!(hash_secret("a"), hash_secret("b"));
    }

    #[tokio::test]
    async fn refresh_round_trips_by_raw_token_and_is_consumed_once() {
        let store = RefreshTokens::default();
        store.insert("raw-token", identity()).await;

        // Lookup hashes the presented value, so the raw token resolves...
        let entry = store.take("raw-token").await.expect("token is live");
        assert_eq!(entry.identity.sub, "u1");
        // ...and rotation/redemption consumes it (replay finds nothing).
        assert!(store.take("raw-token").await.is_none());
    }

    #[tokio::test]
    async fn refresh_rotation_carries_birth_time_and_never_extends_it() {
        let store = RefreshTokens::default();

        // A rotated token must store the *passed* chain birth verbatim, not
        // `Instant::now()` — that's what keeps the absolute TTL from sliding.
        let birth = Instant::now();
        store.insert_rotated("rotated", identity(), birth).await;
        let entry = store.take("rotated").await.expect("token is live");
        assert_eq!(
            entry.issued_at, birth,
            "rotation must not reset the chain clock"
        );

        // A fresh insert, by contrast, stamps ~now.
        let before = Instant::now();
        store.insert("fresh", identity()).await;
        let after = Instant::now();
        let fresh = store.take("fresh").await.expect("token is live");
        assert!(fresh.issued_at >= before && fresh.issued_at <= after);
    }

    #[tokio::test]
    async fn auth_code_round_trips_by_raw_code_and_is_consumed_once() {
        let store = AuthCodes::default();
        store
            .insert(
                "raw-code",
                identity(),
                "challenge".into(),
                "https://app/cb".into(),
                "client-1".into(),
            )
            .await;

        let entry = store.take("raw-code").await.expect("code is live");
        assert_eq!(entry.client_id, "client-1");
        assert!(store.take("raw-code").await.is_none());
    }
}
