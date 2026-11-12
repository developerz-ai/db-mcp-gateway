//! Concurrency budgets (sec qa 2026-06-29 T1; plan 101 slice 09).
//!
//! - The bearer-gated budget (`/mcp`, `/auth/logout`, `/admin/v1/*`) has a
//!   process-wide cap that sheds with `503 service_overloaded` and, after
//!   authentication, a per-identity cap that returns `429 rate_limited` so one
//!   noisy caller can't starve the rest (CLAUDE.md: "One noisy user must not
//!   starve others.").
//! - The unauthenticated OAuth routes get their own, smaller budget. They carry
//!   no session identity, so sharing the gated budget would let anonymous
//!   traffic (stalled bodies, an `/authorize` flood) take `/mcp` down.
//!
//! Permits are held for the request's lifetime and released when the response
//! future completes or is dropped (client disconnect, timeout). Every shed
//! logs, counts `requests_shed_total{scope}` and carries `Retry-After: 1`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::request_id::GatewayRequestId;
use crate::auth::Identity;

/// Soft ceiling on tracked identities. `user_sub` values come from the SSO IdP,
/// so real cardinality is the org's user count — but the map is still bounded so
/// a misbehaving IdP minting unique subs can't grow it without limit. When full,
/// idle identities (all permits available → nothing in flight) are swept before
/// a new one is admitted.
const MAX_TRACKED_IDENTITIES: usize = 16_384;

/// The unauthenticated budget is this fraction of the gated global cap (512 →
/// 64): enough for every real login in flight, small enough that saturating
/// it costs an attacker sockets without touching `/mcp`.
const OAUTH_SHARE_DIVISOR: usize = 8;

/// Which budget shed a request; the `scope` label on `requests_shed_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShedScope {
    Global,
    Identity,
    Oauth,
}

impl ShedScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Identity => "identity",
            Self::Oauth => "oauth",
        }
    }
}

/// Holds the global and per-identity permit pools for one budget.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    global: Arc<Semaphore>,
    global_scope: ShedScope,
    per_identity: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_identity_limit: usize,
    max_tracked: usize,
}

impl ConcurrencyLimiter {
    /// The bearer-gated budget: `global` in-flight requests in total, at most
    /// `per_identity` of them from one `user_sub`.
    pub fn with_caps(global: usize, per_identity: usize) -> Self {
        Self::with_limits(global, per_identity, MAX_TRACKED_IDENTITIES)
    }

    /// The unauthenticated OAuth budget, sized from the gated global cap.
    /// Requests here never carry an `Identity`, so only the global pool applies.
    pub fn unauthenticated(gated_global: usize) -> Self {
        let cap = (gated_global / OAUTH_SHARE_DIVISOR).max(1);
        Self {
            global_scope: ShedScope::Oauth,
            ..Self::with_limits(cap, cap, 0)
        }
    }

    fn with_limits(global: usize, per_identity: usize, max_tracked: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global)),
            global_scope: ShedScope::Global,
            per_identity: Mutex::new(HashMap::new()),
            per_identity_limit: per_identity,
            max_tracked,
        }
    }

    /// A global permit, or `None` when this budget is saturated.
    fn try_global(&self) -> Option<OwnedSemaphorePermit> {
        self.global.clone().try_acquire_owned().ok()
    }

    /// A permit from `user_sub`'s pool, or `None` when that one identity is at
    /// its cap. Pools are created lazily and reclaimed once idle.
    ///
    /// The permit is taken while the map lock is held: released first, a
    /// concurrent sweep could drop this identity's (still idle) semaphore and
    /// a later request would mint a second one — two pools, double the cap.
    async fn try_identity(&self, user_sub: &str) -> Option<OwnedSemaphorePermit> {
        // tokio::sync::Mutex on the request path; no `.await` inside the
        // critical section, so it stays a map lookup plus a try-acquire.
        let mut map = self.per_identity.lock().await;
        if !map.contains_key(user_sub) && map.len() >= self.max_tracked {
            // Drop identities with nothing in flight before admitting a new
            // one, so the map tracks active callers rather than all-time.
            map.retain(|_, sem| sem.available_permits() < self.per_identity_limit);
        }
        map.entry(user_sub.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_identity_limit)))
            .clone()
            .try_acquire_owned()
            .ok()
    }
}

/// Axum middleware enforcing both caps. On the gated routers it runs inside
/// `bearer_auth`, so `Identity` is already in the request extensions; on the
/// OAuth router there is none and only the global pool applies.
pub async fn enforce(
    State(limiter): State<Arc<ConcurrencyLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    // Global first: a cheap check that sheds saturation before touching the
    // per-identity map. Held until this fn returns (response buffered) or the
    // task is dropped on disconnect.
    let Some(_global) = limiter.try_global() else {
        return limited(&req, limiter.global_scope);
    };

    // `_per_identity` is held for the same lifetime as `_global`.
    let _per_identity = match req.extensions().get::<Identity>() {
        Some(identity) => match limiter.try_identity(&identity.user_sub).await {
            Some(permit) => Some(permit),
            None => return limited(&req, ShedScope::Identity),
        },
        None => None,
    };

    next.run(req).await
}

/// Stable-coded rejection body, mirroring the `{ error: { category, code } }`
/// shape the auth middleware returns, plus the request id.
fn limited(req: &Request, scope: ShedScope) -> Response {
    let (status, category, code) = match scope {
        ShedScope::Identity => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "concurrency_limit_exceeded",
        ),
        ShedScope::Global | ShedScope::Oauth => (
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "service_overloaded",
        ),
    };
    let request_id = GatewayRequestId::of(req);
    tracing::warn!(
        %request_id,
        scope = scope.as_str(),
        path = req.uri().path(),
        "request shed by concurrency cap"
    );
    metrics::counter!("requests_shed_total", "scope" => scope.as_str()).increment(1);
    let body = json!({
        "error": { "category": category, "code": code },
        "request_id": request_id.to_string(),
    });
    let mut response = (status, Json(body)).into_response();
    // Coarse hint for well-behaved clients; permits free the instant in-flight
    // requests finish, so a short delay is enough.
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[cfg(test)]
#[path = "limit_tests.rs"]
mod tests;
