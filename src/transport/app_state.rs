//! Process-wide state shared with every request handler.
//!
//! Cloned per request — internals are `Arc`-shared so cloning is cheap. Kept in
//! `transport/` because everything here is HTTP-layer plumbing; the auth
//! primitives themselves live under `crate::auth`.
//!
//! `auth = None` is the test bootstrap (no IdP, no state DB needed). The
//! production binary always sets `Some(AuthFacade)`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::auth::{AuthConfig, OidcClient, SessionStore};

/// `state → nonce` from /auth/login lives here until /auth/callback consumes
/// (and removes) it. TTL-bounded so a wedged login can't accumulate.
const FLOW_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct AppState {
    pub auth: Option<AuthFacade>,
}

#[derive(Clone)]
pub struct AuthFacade {
    pub config: Arc<AuthConfig>,
    pub sessions: SessionStore,
    pub oidc: OidcClient,
    pub flows: PendingFlows,
}

#[derive(Clone, Default)]
pub struct PendingFlows {
    inner: Arc<Mutex<HashMap<String, PendingFlow>>>,
}

#[derive(Debug, Clone)]
struct PendingFlow {
    nonce: String,
    expires_at: Instant,
}

impl PendingFlows {
    pub async fn insert(&self, state: String, nonce: String) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            state,
            PendingFlow {
                nonce,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
    }

    /// Remove and return the nonce for a given state, if still live.
    pub async fn take(&self, state: &str) -> Option<String> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(state).map(|flow| flow.nonce)
    }

    fn gc(map: &mut HashMap<String, PendingFlow>) {
        let now = Instant::now();
        map.retain(|_, flow| flow.expires_at > now);
    }
}
