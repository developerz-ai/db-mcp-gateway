//! Per-router time and size bounds (plan 101 slice 09 step 2).
//!
//! Every router gets a whole-request timeout, a request-body deadline and an
//! explicit body-size limit. A request past its timeout is dropped — for
//! `/mcp` that is the same path as a client disconnect (target query
//! cancelled, audit row `cancelled`) — and answered `504`. A body that has not
//! fully arrived by the deadline fails extraction, which frees the
//! concurrency permit a slow-loris sender would otherwise pin. The OAuth
//! routes read the body before taking a permit at all ([`buffer_oauth_body`]).

use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tower_http::timeout::{RequestBodyDeadlineLayer, TimeoutLayer};

use crate::audit::AUDIT_WRITE_TIMEOUT;
use crate::auth::oidc::LOGIN_IDP_BUDGET;
use crate::exec::DEFAULT_STATEMENT_TIMEOUT_MS;

/// Time for a client to deliver a whole request body.
const BODY_READ_DEADLINE: Duration = Duration::from_secs(10);
/// OAuth forms are a few hundred bytes; a sender still dribbling after this
/// is not a real client.
const OAUTH_BODY_DEADLINE: Duration = Duration::from_secs(5);

/// `/mcp`: the waits one call can stack in sequence — the caller's pool
/// share, then a pool connection (both bounded at 5 s by the adapters), the
/// statement ceiling, the intent and outcome audit writes — plus slack for
/// the adapters' 0.5 s past the ceiling, authz and serialisation. 75 s.
pub const MCP_TIMEOUT: Duration = Duration::from_millis(
    DEFAULT_STATEMENT_TIMEOUT_MS as u64
        + CALLER_SLOT_ALLOWANCE.as_millis() as u64
        + POOL_ACQUIRE_ALLOWANCE.as_millis() as u64
        + 2 * AUDIT_WRITE_TIMEOUT.as_millis() as u64
        + SLACK.as_millis() as u64,
);
const CALLER_SLOT_ALLOWANCE: Duration = Duration::from_secs(5);
const POOL_ACQUIRE_ALLOWANCE: Duration = Duration::from_secs(5);
/// Covers the exec layer's 0.5 s timer slack past the statement ceiling.
const SLACK: Duration = Duration::from_secs(5);

/// OAuth / login routes: `/auth/callback` waits on the IdP — discovery, the
/// code exchange, a JWKS fetch — which `auth::oidc` bounds as a whole, then
/// writes the session. The handler has to give up first: it still redirects
/// the browser back to the client, where this deadline answers a bare `504`.
/// 60 s.
const OAUTH_TIMEOUT: Duration =
    Duration::from_secs(LOGIN_IDP_BUDGET.as_secs() + AFTER_IDP_ALLOWANCE.as_secs());
/// State-DB writes and the response after the IdP has answered.
const AFTER_IDP_ALLOWANCE: Duration = Duration::from_secs(10);
/// Admin API: a handful of state-DB statements in one transaction.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Probes and discovery documents: in-memory, or `/readyz`'s 2 s DB probe.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// SQL text plus arguments; generous for any hand-written query.
const MCP_BODY_LIMIT: usize = 1024 * 1024;
/// OAuth forms and DCR metadata are a few hundred bytes.
const OAUTH_BODY_LIMIT: usize = 16 * 1024;
/// Admin JSON bodies: one user, database or grant.
const ADMIN_BODY_LIMIT: usize = 64 * 1024;
/// Probes and discovery are GETs.
const OPEN_BODY_LIMIT: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub(super) enum Bounds {
    Mcp,
    OAuth,
    Admin,
    Open,
}

impl Bounds {
    fn timeout(self) -> Duration {
        match self {
            Self::Mcp => MCP_TIMEOUT,
            Self::OAuth => OAUTH_TIMEOUT,
            Self::Admin => ADMIN_TIMEOUT,
            Self::Open => OPEN_TIMEOUT,
        }
    }

    fn body_limit(self) -> usize {
        match self {
            Self::Mcp => MCP_BODY_LIMIT,
            Self::OAuth => OAUTH_BODY_LIMIT,
            Self::Admin => ADMIN_BODY_LIMIT,
            Self::Open => OPEN_BODY_LIMIT,
        }
    }

    /// Wrap every route already on `router`. Apply after the route layers so
    /// the timeout also covers authentication and the concurrency wait.
    pub(super) fn apply<S>(self, router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        router
            .layer(DefaultBodyLimit::max(self.body_limit()))
            .layer(RequestBodyDeadlineLayer::new(BODY_READ_DEADLINE))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::GATEWAY_TIMEOUT,
                self.timeout(),
            ))
    }
}

/// Read the whole body (≤ [`OAUTH_BODY_LIMIT`], within
/// [`OAUTH_BODY_DEADLINE`]) before the OAuth budget's permit is taken.
/// Those routes are open, so without this 64 slow senders would hold every
/// permit and shed each real login and refresh.
pub(super) async fn buffer_oauth_body(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let read = tokio::time::timeout(OAUTH_BODY_DEADLINE, to_bytes(body, OAUTH_BODY_LIMIT)).await;
    match read {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        // Over the limit, or the outer body deadline fired first.
        Ok(Err(_)) => body_refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large or unreadable",
        ),
        Err(_) => body_refused(
            StatusCode::REQUEST_TIMEOUT,
            "request body not received in time",
        ),
    }
}

/// RFC 6749 §5.2 shape, as the OAuth handlers answer an undecodable body.
fn body_refused(status: StatusCode, description: &str) -> Response {
    let body = json!({ "error": "invalid_request", "error_description": description });
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_timeout_outlasts_every_wait_a_call_stacks() {
        let statement = Duration::from_millis(u64::from(DEFAULT_STATEMENT_TIMEOUT_MS) + 500);
        let floor =
            CALLER_SLOT_ALLOWANCE + POOL_ACQUIRE_ALLOWANCE + statement + 2 * AUDIT_WRITE_TIMEOUT;
        assert!(MCP_TIMEOUT > floor, "{MCP_TIMEOUT:?} <= {floor:?}");
    }

    /// Operator docs quote 75 s (and an 80 s drain built on it).
    #[test]
    fn mcp_timeout_is_the_documented_75_seconds() {
        assert_eq!(MCP_TIMEOUT, Duration::from_secs(75));
    }

    /// The login handler's own IdP budget must run out first, with room for
    /// the session write, or the router answers the callback with a raw 504.
    #[test]
    fn oauth_timeout_outlasts_the_idp_login_budget() {
        let floor = LOGIN_IDP_BUDGET + Duration::from_secs(5);
        assert!(OAUTH_TIMEOUT >= floor, "{OAUTH_TIMEOUT:?} < {floor:?}");
        assert_eq!(OAUTH_TIMEOUT, Duration::from_secs(60));
    }
}
