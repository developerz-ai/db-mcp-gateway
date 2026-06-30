//! Concurrency limiting for the bearer-gated router.
//!
//! Two independent caps keep the query path from becoming a resource-exhaustion
//! vector (sec qa 2026-06-29 T1):
//!
//! - A process-wide cap sheds load with `503` when the gateway is saturated, so
//!   a burst can't pile unbounded tasks against every DB pool at once.
//! - A per-identity cap returns `429` so one noisy agent can't consume the whole
//!   global budget and starve other users (CLAUDE.md: "One noisy user must not
//!   starve others.").
//!
//! Both permits are held for the request's lifetime and released when the
//! response future completes — or when the client disconnects and the task is
//! dropped — mirroring the SSE connection cap in `sse.rs`. The gated routes
//! return fully-buffered JSON (not streams), so "response future completes" is
//! the instant the handler is done.

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

use crate::auth::Identity;

/// Process-wide ceiling on concurrent in-flight gated requests. Comfortably
/// above any realistic agent fan-out for an internal single-tenant gateway,
/// while bounding task/memory growth under a flood. Same order of magnitude as
/// the SSE connection cap (`sse.rs`).
const MAX_CONCURRENT_REQUESTS: usize = 512;

/// Ceiling on concurrent in-flight requests for a single SSO identity. One agent
/// rarely needs more than a handful of parallel queries; capping here stops a
/// single caller from monopolizing the global budget.
const MAX_CONCURRENT_PER_IDENTITY: usize = 16;

/// Soft ceiling on tracked identities. `user_sub` values come from the SSO IdP,
/// so real cardinality is the org's user count — but the map is still bounded so
/// a misbehaving IdP minting unique subs can't grow it without limit. When full,
/// idle identities (all permits available → nothing in flight) are swept before
/// a new one is admitted.
const MAX_TRACKED_IDENTITIES: usize = 16_384;

/// Holds the global and per-identity permit pools for the gated router.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    global: Arc<Semaphore>,
    per_identity: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_identity_limit: usize,
    max_tracked: usize,
}

impl ConcurrencyLimiter {
    /// Production limiter sized by the module constants.
    pub fn new() -> Self {
        Self::with_limits(
            MAX_CONCURRENT_REQUESTS,
            MAX_CONCURRENT_PER_IDENTITY,
            MAX_TRACKED_IDENTITIES,
        )
    }

    fn with_limits(global: usize, per_identity: usize, max_tracked: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global)),
            per_identity: Mutex::new(HashMap::new()),
            per_identity_limit: per_identity,
            max_tracked,
        }
    }

    /// A global permit, or `None` when the whole gateway is saturated.
    fn try_global(&self) -> Option<OwnedSemaphorePermit> {
        self.global.clone().try_acquire_owned().ok()
    }

    /// A permit from `user_sub`'s pool, or `None` when that one identity is at
    /// its cap. Pools are created lazily and reclaimed once idle.
    async fn try_identity(&self, user_sub: &str) -> Option<OwnedSemaphorePermit> {
        let semaphore = {
            // tokio::sync::Mutex on the request path; the critical section is a
            // map lookup/insert with no `.await` inside, so it stays tiny.
            let mut map = self.per_identity.lock().await;
            if !map.contains_key(user_sub) && map.len() >= self.max_tracked {
                // Drop identities with nothing in flight before admitting a new
                // one, so the map tracks active callers rather than all-time.
                map.retain(|_, sem| sem.available_permits() < self.per_identity_limit);
            }
            map.entry(user_sub.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_identity_limit)))
                .clone()
        };
        semaphore.try_acquire_owned().ok()
    }
}

impl Default for ConcurrencyLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum middleware enforcing both caps. Mounted on the gated router *after*
/// `bearer_auth` (i.e. added before it, so it runs inside it), so `Identity` is
/// already in the request extensions. Its absence means the auth-less test
/// bootstrap, where per-identity limiting is skipped; the global cap still
/// applies.
pub async fn enforce(
    State(limiter): State<Arc<ConcurrencyLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    // Global first: a cheap check that sheds saturation before touching the
    // per-identity map. Held until this fn returns (response buffered) or the
    // task is dropped on disconnect.
    let Some(_global) = limiter.try_global() else {
        return limited(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "service_overloaded",
        );
    };

    // `_per_identity` is held for the same lifetime as `_global`.
    let _per_identity = match req.extensions().get::<Identity>() {
        Some(identity) => match limiter.try_identity(&identity.user_sub).await {
            Some(permit) => Some(permit),
            None => {
                return limited(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    "concurrency_limit_exceeded",
                );
            }
        },
        None => None,
    };

    next.run(req).await
}

/// Stable-coded rejection body, mirroring the `{ error: { category, code } }`
/// shape the auth middleware returns.
fn limited(status: StatusCode, category: &str, code: &str) -> Response {
    let mut response = (
        status,
        Json(json!({ "error": { "category": category, "code": code } })),
    )
        .into_response();
    // Coarse hint for well-behaved clients; permits free the instant in-flight
    // requests finish, so a short delay is enough.
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn global_cap_sheds_when_exhausted() {
        let limiter = ConcurrencyLimiter::with_limits(2, 8, 16);
        let p1 = limiter.try_global().expect("first permit");
        let _p2 = limiter.try_global().expect("second permit");
        assert!(limiter.try_global().is_none(), "third must shed");
        drop(p1);
        assert!(limiter.try_global().is_some(), "freed slot is reusable");
    }

    #[tokio::test]
    async fn per_identity_cap_is_independent_across_users() {
        let limiter = ConcurrencyLimiter::with_limits(100, 1, 16);
        let alice = limiter.try_identity("alice").await.expect("alice slot");
        assert!(
            limiter.try_identity("alice").await.is_none(),
            "alice is over her cap"
        );
        // Bob's cap is independent of alice's exhaustion.
        let _bob = limiter.try_identity("bob").await.expect("bob slot");
        drop(alice);
        assert!(
            limiter.try_identity("alice").await.is_some(),
            "freed alice slot is reusable"
        );
    }

    #[tokio::test]
    async fn idle_identities_are_swept_when_map_is_full() {
        let limiter = ConcurrencyLimiter::with_limits(100, 2, 2);
        // Two identities go idle (acquired then released).
        drop(limiter.try_identity("alice").await.expect("alice"));
        drop(limiter.try_identity("bob").await.expect("bob"));
        // A third distinct identity triggers a sweep of the two idle entries.
        let _carol = limiter.try_identity("carol").await.expect("carol");
        let map = limiter.per_identity.lock().await;
        assert!(map.contains_key("carol"));
        assert!(
            map.len() <= limiter.max_tracked,
            "map stays bounded after sweep: {}",
            map.len()
        );
    }

    #[tokio::test]
    async fn active_identities_survive_a_sweep() {
        let limiter = ConcurrencyLimiter::with_limits(100, 2, 1);
        // alice holds a permit → active, must not be swept when carol arrives.
        let _alice = limiter.try_identity("alice").await.expect("alice");
        let _carol = limiter.try_identity("carol").await.expect("carol");
        let map = limiter.per_identity.lock().await;
        assert!(
            map.contains_key("alice"),
            "active identity must survive sweep"
        );
    }
}
