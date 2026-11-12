//! The auth handles every auth-aware HTTP handler reads through `AppState.auth`,
//! and the session/token operations that span more than one of them.

use std::sync::Arc;

use arc_swap::ArcSwap;

use super::{AuthCodes, GrantIdentity, Minted, PendingFlows, RefreshTokens};
use crate::auth::{
    AuthConfig, AuthError, Identity, OidcClient, ServiceTokenStore, SessionId, SessionStore,
    jwt::SessionJwt,
};

#[derive(Clone, Debug)]
pub struct AuthFacade {
    pub config: Arc<AuthConfig>,
    /// Session-JWT signer/verifier, keys built once from
    /// `config.session_signing_key` rather than per request.
    pub jwt: SessionJwt,
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
    /// `service_accounts:` at boot and swapped whole on config reload, so a
    /// request sees either the old or the new set, never a mix. Empty when the
    /// config declares none — `bearer_auth` then falls straight through to the
    /// session-JWT path.
    pub service_tokens: Arc<ArcSwap<ServiceTokenStore>>,
}

/// The bearer pair a `/token` response carries. `Debug` redacts both tokens.
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for IssuedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedTokens")
            .field("expires_in_secs", &self.expires_in_secs)
            .finish_non_exhaustive()
    }
}

impl AuthFacade {
    /// Fresh authorization: a new session, its access JWT, and a refresh token
    /// starting a new chain paired with that session.
    pub async fn issue_tokens(
        &self,
        identity: GrantIdentity,
        refresh_token: String,
    ) -> Result<IssuedTokens, AuthError> {
        let minted = self
            .refresh
            .mint(
                &self.sessions,
                identity,
                refresh_token,
                self.config.session_ttl,
            )
            .await?;
        self.bearer_pair(minted)
    }

    /// Refresh grant: rotate `presented` into `refresh_token`, revoking the
    /// session the old token was paired with. `Ok(None)` → `invalid_grant`.
    pub async fn rotate_tokens(
        &self,
        presented: &str,
        refresh_token: String,
    ) -> Result<Option<IssuedTokens>, AuthError> {
        self.refresh
            .rotate(
                &self.sessions,
                presented,
                refresh_token,
                self.config.session_ttl,
            )
            .await?
            .map(|minted| self.bearer_pair(minted))
            .transpose()
    }

    /// RFC 7009 revocation of either token kind. `Ok` for an unknown, expired or
    /// forged token (§2.2); `Err` only when the state DB failed, so the caller
    /// can answer 503 instead of claiming a revoke that did not happen.
    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        if self.refresh.revoke(&self.sessions, token).await? {
            return Ok(());
        }
        match self.jwt.verify(token) {
            Ok(claims) => self.sessions.revoke(SessionId::from(claims.sid)).await,
            Err(_) => Ok(()),
        }
    }

    /// Logout: revoke every session and refresh chain of the caller's subject,
    /// so no other device keeps a live bearer for this identity.
    pub async fn logout(&self, identity: &Identity) -> Result<usize, AuthError> {
        self.refresh
            .end_all_for_sub(&self.sessions, &identity.user_sub)
            .await
    }

    fn bearer_pair(&self, minted: Minted) -> Result<IssuedTokens, AuthError> {
        let access_token = self.jwt.issue(
            minted.session.id,
            &minted.session.user_sub,
            self.config.session_ttl,
        )?;
        Ok(IssuedTokens {
            access_token,
            refresh_token: minted.refresh_token,
            expires_in_secs: self.config.session_ttl.as_secs(),
        })
    }
}
