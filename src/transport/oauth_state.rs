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

use tokio::sync::Mutex;

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
    inner: Arc<Mutex<HashMap<String, AuthCode>>>,
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
        code: String,
        identity: GrantIdentity,
        code_challenge: String,
        redirect_uri: String,
        client_id: String,
    ) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            code,
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
        map.remove(code)
    }

    fn gc(map: &mut HashMap<String, AuthCode>) {
        let now = Instant::now();
        map.retain(|_, code| code.expires_at > now);
    }
}

/// Lifetime of a refresh token. Long enough that a developer rarely re-does the
/// browser login, short enough to bound a leaked token's usefulness.
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Refresh-token store: token → the verified identity it renews. Rotated on
/// every redemption (the old token is removed, a new one issued), per OAuth 2.1
/// §4.3.1 for public clients. In-memory like the other flow state — see the
/// deployment note on single-replica / sticky routing for the auth dance.
#[derive(Clone, Default, Debug)]
pub struct RefreshTokens {
    inner: Arc<Mutex<HashMap<String, RefreshToken>>>,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub identity: GrantIdentity,
    expires_at: Instant,
}

impl RefreshTokens {
    pub async fn insert(&self, token: String, identity: GrantIdentity) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            token,
            RefreshToken {
                identity,
                expires_at: Instant::now() + REFRESH_TTL,
            },
        );
    }

    /// Remove and return a refresh token (rotation consumes it), if still live.
    pub async fn take(&self, token: &str) -> Option<RefreshToken> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(token)
    }

    fn gc(map: &mut HashMap<String, RefreshToken>) {
        let now = Instant::now();
        map.retain(|_, t| t.expires_at > now);
    }
}
