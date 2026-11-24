//! Concurrency budgets (sec qa 2026-06-29 T1; plan 101 slice 09).
//!
//! - The bearer-gated budget (`/mcp`, `/auth/logout`, `/admin/v1/*`) has a
//!   process-wide cap that sheds with `503 service_overloaded` and, after
//!   authentication, a per-identity cap that returns `429 rate_limited` so one
//!   noisy caller can't starve the rest (CLAUDE.md: "One noisy user must not
//!   starve others."). A service account may set its own cap
//!   (`service_accounts[].max_concurrent_requests`, plan 101 slice 12).
//! - The unauthenticated OAuth routes get their own, smaller budget. They carry
//!   no session identity, so sharing the gated budget would let anonymous
//!   traffic (stalled bodies, an `/authorize` flood) take `/mcp` down.
//!
//! Permits are held for the request's lifetime and released when the response
//! future completes or is dropped (client disconnect, timeout). Every shed
//! logs, counts `requests_shed_total{scope}` and carries `Retry-After: 1`.
//! On the MCP endpoint the shed body is a JSON-RPC error and every
//! identity-capped answer carries the caller's budget headers (spec 03
//! §Resource safety).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::auth::{Identity, ServicePolicy};
use shed::{insert_budget, limited};

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

/// One identity's permit pool and the cap it was sized for.
#[derive(Debug)]
struct IdentityPool {
    permits: Arc<Semaphore>,
    cap: usize,
}

impl IdentityPool {
    fn new(cap: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(cap)),
            cap,
        }
    }

    fn is_idle(&self) -> bool {
        self.permits.available_permits() >= self.cap
    }
}

/// A per-identity permit and the budget it was taken from.
#[derive(Debug)]
struct IdentityPermit {
    _permit: OwnedSemaphorePermit,
    limit: usize,
    remaining: usize,
}

/// Holds the global and per-identity permit pools for one budget.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    global: Arc<Semaphore>,
    global_scope: ShedScope,
    per_identity: Mutex<HashMap<String, IdentityPool>>,
    per_identity_limit: usize,
    max_tracked: usize,
    /// Requests to this path are MCP: shed as JSON-RPC, budget in headers.
    mcp_path: Option<String>,
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
            mcp_path: None,
        }
    }

    /// Answer requests to `path` (the MCP endpoint) in MCP terms: a shed is
    /// a JSON-RPC error, an admitted request reports its identity budget.
    pub fn with_mcp_path(self, path: &str) -> Self {
        Self {
            mcp_path: Some(path.to_owned()),
            ..self
        }
    }

    fn is_mcp(&self, req: &Request) -> bool {
        self.mcp_path.as_deref() == Some(req.uri().path())
    }

    fn identity_cap(&self, account_cap: Option<usize>) -> usize {
        account_cap.unwrap_or(self.per_identity_limit)
    }

    /// A global permit, or `None` when this budget is saturated.
    fn try_global(&self) -> Option<OwnedSemaphorePermit> {
        self.global.clone().try_acquire_owned().ok()
    }

    /// A permit from `user_sub`'s pool, or `None` when that one identity is at
    /// its cap — `account_cap` (a service account's own) or the per-identity
    /// default. Pools are created lazily and reclaimed once idle.
    ///
    /// The permit is taken while the map lock is held: released first, a
    /// concurrent sweep could drop this identity's (still idle) semaphore and
    /// a later request would mint a second one — two pools, double the cap.
    async fn try_identity(
        &self,
        user_sub: &str,
        account_cap: Option<usize>,
    ) -> Option<IdentityPermit> {
        let cap = self.identity_cap(account_cap);
        // tokio::sync::Mutex on the request path; no `.await` inside the
        // critical section, so it stays a map lookup plus a try-acquire.
        let mut map = self.per_identity.lock().await;
        if !map.contains_key(user_sub) && map.len() >= self.max_tracked {
            // Drop identities with nothing in flight before admitting a new
            // one, so the map tracks active callers rather than all-time.
            map.retain(|_, pool| !pool.is_idle());
        }
        let pool = map
            .entry(user_sub.to_owned())
            .or_insert_with(|| IdentityPool::new(cap));
        if pool.cap != cap {
            // The account's cap changed on a reload. Permits already out on
            // the old pool finish there; new requests count against the new
            // cap from now on.
            *pool = IdentityPool::new(cap);
        }
        let permit = pool.permits.clone().try_acquire_owned().ok()?;
        Some(IdentityPermit {
            _permit: permit,
            limit: cap,
            remaining: pool.permits.available_permits(),
        })
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
        return limited(&req, limiter.global_scope, limiter.is_mcp(&req));
    };

    // `_per_identity` is held for the same lifetime as `_global`.
    let account_cap = req
        .extensions()
        .get::<ServicePolicy>()
        .and_then(|policy| policy.max_concurrent_requests);
    let per_identity = match req.extensions().get::<Identity>() {
        Some(identity) => match limiter.try_identity(&identity.user_sub, account_cap).await {
            Some(permit) => Some(permit),
            None => {
                let mut response = limited(&req, ShedScope::Identity, limiter.is_mcp(&req));
                if limiter.is_mcp(&req) {
                    insert_budget(&mut response, limiter.identity_cap(account_cap), 0);
                }
                return response;
            }
        },
        None => None,
    };

    let report_budget = limiter.is_mcp(&req);
    let mut response = next.run(req).await;
    if let Some(permit) = per_identity.as_ref().filter(|_| report_budget) {
        insert_budget(&mut response, permit.limit, permit.remaining);
    }
    response
}

#[path = "limit_shed.rs"]
mod shed;

#[cfg(test)]
#[path = "limit_tests.rs"]
mod tests;
