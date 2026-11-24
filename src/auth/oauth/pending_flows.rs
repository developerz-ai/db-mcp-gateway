//! Pending IdP logins: a login started by `/auth/login` (or a bridged
//! `/authorize`) waits here, keyed by its OIDC `state`, until `/auth/callback`
//! consumes it. A bridged login to a non-loopback redirect then waits here once
//! more, as a [`PendingConsent`], until the user approves or denies it.
//!
//! Two backends behind one API, as for [`super::ClientRegistry`]:
//! - **DB** (`with_db`) — production. Rows in the shared state DB (migration
//!   0022), so the replica the IdP or the consent form lands on need not be
//!   the one that started the login: no sticky routing (spec 02 §HA).
//! - **Memory** (`default`) — unit tests and the auth-less test bootstrap.

use std::sync::Arc;

use chrono::Duration;
use secrecy::{ExposeSecret, SecretSlice};
use sqlx::PgPool;

use super::login_secrets::{FlowKey, LoginSecrets};
use super::pending_flows_mem::MemoryFlows;
use super::{ClientName, GrantIdentity, StoreError, hash_secret, pending_flows_db as db};
use crate::auth::pkce::ct_eq;

/// Cap on pending flows. A login produces one pending flow; this cap bounds
/// resource exhaustion from abandoning many browser logins. At the cap the
/// oldest flow is evicted — `/authorize` is unauthenticated, so refusing would
/// let a flood block every real login.
pub(super) const PENDING_FLOWS_MAX_SIZE: usize = 10_000;

/// TTL-bounded so a wedged login can't accumulate.
///
/// 15 min (was 5): a real browser SSO leg includes the IdP login form, a TOTP
/// prompt, and — when the IdP's user store is briefly slow — multi-second
/// backend waits. 5 min expired legitimate logins mid-flow, surfacing at
/// /auth/callback as a missing flow. The store is still size-capped
/// (`PENDING_FLOWS_MAX_SIZE`), so a longer TTL can't let abandoned flows grow
/// unbounded.
pub(super) const FLOW_TTL: Duration = Duration::minutes(15);

/// How long a rendered consent page stays actionable. Long enough to read it;
/// the user is already signed in, so there is no IdP leg to wait on.
pub(super) const CONSENT_TTL: Duration = Duration::minutes(10);

/// Cap on consents awaiting a decision. Each one costs a completed IdP login,
/// so a flood is bounded by real sign-ins; at the cap the soonest-expiring
/// consent is dropped rather than refusing a new one.
pub(super) const PENDING_CONSENTS_MAX_SIZE: usize = 1_000;

/// Pending consents one subject may hold. A user looping silent SSO logins
/// displaces only their own oldest consent; the global cap is a backstop.
pub(super) const PENDING_CONSENTS_PER_SUBJECT: usize = 5;

/// Context an MCP OAuth-bridge `/authorize` request stashes across the IdP
/// round-trip. Recovered at `/auth/callback` (keyed by the OIDC `state`) so the
/// gateway can mint an authorization code and 302 back to the *client's* own
/// redirect URI — the loopback Claude Code listens on.
#[derive(Clone)]
pub struct OAuthBridge {
    /// The client_id from `/register` — carried through so `/token` can verify
    /// the presenter matches the registrant.
    pub client_id: String,
    /// The registrant's self-asserted name, for the consent page only.
    pub client_name: Option<ClientName>,
    /// The MCP client's registered redirect URI (loopback or https).
    pub client_redirect_uri: String,
    /// The MCP client's `state` — echoed back verbatim on the final redirect.
    pub client_state: String,
    /// PKCE challenge (S256). Verified against `code_verifier` at `/token`.
    pub code_challenge: String,
    /// RFC 8707 `resource` the client sent; `/authorize` has already checked
    /// that it names this gateway.
    pub resource: Option<String>,
}

#[derive(Clone)]
pub struct PendingFlows {
    key: FlowKey,
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Db(PgPool),
    Memory(Arc<MemoryFlows>),
}

impl Default for PendingFlows {
    fn default() -> Self {
        Self {
            key: FlowKey::random(),
            backend: Backend::Memory(Arc::default()),
        }
    }
}

/// A verified login whose authorization code is held back until the user
/// approves the client on the gateway's consent page (the MCP "confused
/// deputy" mitigation for dynamically registered, non-loopback clients).
pub struct PendingConsent {
    pub identity: GrantIdentity,
    pub bridge: OAuthBridge,
    pub(super) csrf_hash: [u8; 32],
}

impl PendingConsent {
    /// Constant-time match of the form's CSRF token against the one rendered.
    pub fn csrf_matches(&self, presented: &str) -> bool {
        ct_eq(&self.csrf_hash, &hash_secret(presented))
    }
}

/// A live login taken at `/auth/callback`, with its re-derived secrets.
#[derive(Clone)]
pub struct PendingFlow {
    pub nonce: String,
    /// PKCE `code_verifier` the gateway (as an OAuth *client*) sends to the
    /// upstream IdP at the token exchange — distinct from any client-facing
    /// PKCE in `bridge`.
    pub idp_verifier: String,
    /// `Some` for an MCP OAuth-bridge login; `None` for the bespoke
    /// `/auth/login` flow that returns the session token as JSON.
    pub bridge: Option<OAuthBridge>,
}

impl PendingFlows {
    /// Production store in the shared state DB (migration 0022 must have run
    /// — `state::connect` does). Replicas derive login secrets from
    /// `signing_key`, so they must share it — as they must for bearers.
    pub fn with_db(pool: PgPool, signing_key: &SecretSlice<u8>) -> Self {
        Self {
            key: FlowKey::from_signing_key(signing_key.expose_secret()),
            backend: Backend::Db(pool),
        }
    }

    /// The nonce and IdP PKCE pair for the login keyed by `state`; send them
    /// to the IdP, then [`Self::insert`] or [`Self::insert_bridge`] the flow.
    pub fn login_secrets(&self, state: &str) -> LoginSecrets {
        self.key.secrets(state)
    }

    /// Hold a bespoke `/auth/login` flow until its callback.
    pub async fn insert(&self, state: &str) -> Result<(), StoreError> {
        self.insert_flow(state, None).await
    }

    /// Hold a flow carrying MCP OAuth-bridge context (the client redirect /
    /// state / PKCE challenge to honor once the IdP round-trip completes).
    pub async fn insert_bridge(&self, state: &str, bridge: OAuthBridge) -> Result<(), StoreError> {
        self.insert_flow(state, Some(bridge)).await
    }

    async fn insert_flow(
        &self,
        state: &str,
        bridge: Option<OAuthBridge>,
    ) -> Result<(), StoreError> {
        let state_hash = hash_secret(state);
        match &self.backend {
            Backend::Db(pool) => db::insert(pool, &state_hash, bridge.as_ref()).await,
            Backend::Memory(memory) => {
                memory.insert(state_hash, bridge).await;
                Ok(())
            }
        }
    }

    /// Remove and return the pending flow for `state`, if still live. Of two
    /// concurrent takes of one `state`, at most one gets it.
    pub async fn take(&self, state: &str) -> Result<Option<PendingFlow>, StoreError> {
        let state_hash = hash_secret(state);
        let taken = match &self.backend {
            Backend::Db(pool) => db::take(pool, &state_hash).await?,
            Backend::Memory(memory) => memory.take(&state_hash).await,
        };
        Ok(taken.map(|bridge| {
            let LoginSecrets {
                nonce,
                idp_verifier,
            } = self.login_secrets(state);
            PendingFlow {
                nonce,
                idp_verifier,
                bridge,
            }
        }))
    }

    /// Hold a verified login until the user decides on its consent page.
    /// `consent_id` keys the entry; `csrf` must come back with the decision.
    pub async fn insert_consent(
        &self,
        consent_id: &str,
        csrf: &str,
        identity: GrantIdentity,
        bridge: OAuthBridge,
    ) -> Result<(), StoreError> {
        let consent_hash = hash_secret(consent_id);
        let consent = PendingConsent {
            identity,
            bridge,
            csrf_hash: hash_secret(csrf),
        };
        match &self.backend {
            Backend::Db(pool) => db::insert_consent(pool, &consent_hash, &consent).await,
            Backend::Memory(memory) => {
                memory.insert_consent(consent_hash, consent).await;
                Ok(())
            }
        }
    }

    /// Remove and return a live consent. Single-use: taken before the CSRF
    /// check, so a wrong token burns the entry instead of allowing guesses.
    pub async fn take_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<PendingConsent>, StoreError> {
        let consent_hash = hash_secret(consent_id);
        match &self.backend {
            Backend::Db(pool) => db::take_consent(pool, &consent_hash).await,
            Backend::Memory(memory) => Ok(memory.take_consent(&consent_hash).await),
        }
    }

    /// Remove all expired flows and consents; returns how many were removed.
    /// Called periodically by the auth GC loop; logs its own DB failure.
    pub async fn gc_expired(&self) -> u64 {
        match &self.backend {
            Backend::Db(pool) => db::gc_expired(pool).await,
            Backend::Memory(memory) => memory.gc_expired().await,
        }
    }

    #[cfg(test)]
    pub(super) fn memory(&self) -> Option<&MemoryFlows> {
        match &self.backend {
            Backend::Memory(memory) => Some(memory),
            Backend::Db(_) => None,
        }
    }
}

#[cfg(test)]
#[path = "pending_flows_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pending_flows_consent_tests.rs"]
mod consent_tests;
