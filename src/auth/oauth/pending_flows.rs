//! Pending IdP logins: `state → nonce` from `/auth/login` (or a bridged
//! `/authorize`) lives here until `/auth/callback` consumes it.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Size cap on the pending flows map. A login produces one pending flow;
/// this cap bounds resource exhaustion from abandoning many browser logins.
/// At the cap the oldest flow is evicted — `/authorize` is unauthenticated, so
/// refusing would let a flood block every real login.
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
    inner: Arc<Mutex<Flows>>,
}

#[derive(Default, Debug)]
struct Flows {
    by_state: HashMap<String, PendingFlow>,
    /// Insertion order. Every flow has the same TTL, so the front is both the
    /// oldest and the first to expire. May hold states already taken; those
    /// are skipped on eviction and dropped by `gc_expired`.
    order: VecDeque<String>,
}

impl Flows {
    /// Drop the oldest still-present flow, skipping taken ones. O(1) amortized.
    fn evict_oldest(&mut self) {
        while let Some(state) = self.order.pop_front() {
            if self.by_state.remove(&state).is_some() {
                return;
            }
        }
    }
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
        let mut flows = self.inner.lock().await;
        if flows.by_state.len() >= PENDING_FLOWS_MAX_SIZE && !flows.by_state.contains_key(&state) {
            flows.evict_oldest();
        }
        flows.order.push_back(state.clone());
        flows.by_state.insert(
            state,
            PendingFlow {
                nonce,
                idp_verifier,
                bridge,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
    }

    /// Remove and return the pending flow for a given state, if still live
    /// (i.e., not yet expired past the flow TTL).
    pub async fn take(&self, state: &str) -> Option<PendingFlow> {
        let flow = self.inner.lock().await.by_state.remove(state)?;
        (flow.expires_at > Instant::now()).then_some(flow)
    }

    /// Remove all expired flows and compact the insertion order; returns how
    /// many flows were removed. Called periodically by a background task.
    pub async fn gc_expired(&self) -> u64 {
        let mut flows = self.inner.lock().await;
        let now = Instant::now();
        let before = flows.by_state.len();
        flows.by_state.retain(|_, flow| flow.expires_at > now);
        let removed = (before - flows.by_state.len()) as u64;
        let Flows { by_state, order } = &mut *flows;
        order.retain(|state| by_state.contains_key(state));
        removed
    }
}

#[cfg(test)]
#[path = "pending_flows_tests.rs"]
mod tests;
