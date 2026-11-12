//! The auth handles every auth-aware HTTP handler reads through `AppState.auth`.

use std::sync::Arc;

use super::{AuthCodes, PendingFlows, RefreshTokens};
use crate::auth::{AuthConfig, OidcClient, ServiceTokenStore, SessionStore};

#[derive(Clone, Debug)]
pub struct AuthFacade {
    pub config: Arc<AuthConfig>,
    pub sessions: SessionStore,
    pub oidc: OidcClient,
    pub flows: PendingFlows,
    /// One-time authorization codes minted by the MCP OAuth bridge
    /// (`/authorize` → IdP → `/auth/callback` → here), redeemed at `/token`.
    /// Unused by the bespoke `/auth/login` JSON flow.
    pub codes: AuthCodes,
    /// Long-lived refresh tokens minted alongside each bridge access token, so
    /// MCP clients can silently renew an expired session without a fresh
    /// browser login. Rotated on every use (OAuth 2.1 public-client rule).
    pub refresh: RefreshTokens,
    /// Static bearer tokens for headless clients (spec 14), resolved from
    /// `service_accounts:` at boot. Empty when the config declares none —
    /// `bearer_auth` then falls straight through to the session-JWT path.
    pub service_tokens: ServiceTokenStore,
}
