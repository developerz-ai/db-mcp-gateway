//! Pending IdP logins: `state → nonce` from `/auth/login` (or a bridged
//! `/authorize`) lives here until `/auth/callback` consumes it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::StoreError;

/// Size cap on the pending flows map. A login produces one pending flow;
/// this cap bounds resource exhaustion from abandoning many browser logins.
const PENDING_FLOWS_MAX_SIZE: usize = 10_000;

/// TTL-bounded so a wedged login can't accumulate.
///
/// 15 min (was 5): a real browser SSO leg includes the IdP login form, a TOTP
/// prompt, and — when the IdP's user store is briefly slow — multi-second
/// backend waits. 5 min expired legitimate logins mid-flow, surfacing at
/// /auth/callback as a missing flow. The store is still size-capped
/// (`PENDING_FLOWS_MAX_SIZE`), so a longer TTL can't let abandoned flows grow
/// unbounded.
const FLOW_TTL: Duration = Duration::from_secs(15 * 60);

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
    pub async fn insert(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
    ) -> Result<(), StoreError> {
        self.insert_flow(state, nonce, idp_verifier, None).await
    }

    /// Insert a flow carrying MCP OAuth-bridge context (the client redirect /
    /// state / PKCE challenge to honor once the IdP round-trip completes).
    pub async fn insert_bridge(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: OAuthBridge,
    ) -> Result<(), StoreError> {
        self.insert_flow(state, nonce, idp_verifier, Some(bridge))
            .await
    }

    async fn insert_flow(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: Option<OAuthBridge>,
    ) -> Result<(), StoreError> {
        let mut map = self.inner.lock().await;
        // Reclaim expired flows before rejecting at cap. The periodic sweep
        // (`spawn_oauth_state_gc`, every 30s) only reaps entries that have
        // crossed `FLOW_TTL` (15 min) — it does nothing against a sustained
        // `/authorize` flood that keeps the map packed with *fresh* junk
        // faster than entries naturally expire. This is unauthenticated
        // (pre-login) traffic, so map.len() at cap is not evidence the
        // gateway is actually busy — it may just mean the sweep hasn't run
        // since the last burst. Trying a GC right here costs one map scan
        // only on the (rare) at-cap path, and immediately frees room for
        // real logins sitting behind a burst that's already aged out.
        if map.len() >= PENDING_FLOWS_MAX_SIZE {
            let now = Instant::now();
            map.retain(|_, flow| flow.expires_at > now);
        }
        if map.len() >= PENDING_FLOWS_MAX_SIZE {
            return Err(StoreError::StoreFull);
        }
        map.insert(
            state,
            PendingFlow {
                nonce,
                idp_verifier,
                bridge,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
        Ok(())
    }

    /// Remove and return the pending flow for a given state, if still live
    /// (i.e., not yet expired past the flow TTL).
    pub async fn take(&self, state: &str) -> Option<PendingFlow> {
        let mut map = self.inner.lock().await;
        if let Some(flow) = map.remove(state) {
            // Check expiration before returning: if the flow has passed its TTL,
            // reject it (treat as if it doesn't exist). The background GC task
            // will clean up the rest.
            if flow.expires_at > Instant::now() {
                Some(flow)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Remove all expired flows. Called periodically by a background task.
    pub async fn gc_expired(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, flow| flow.expires_at > now);
    }
}

#[cfg(test)]
#[path = "pending_flows_tests.rs"]
mod tests;
