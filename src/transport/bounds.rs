//! Per-router time and size bounds (plan 101 slice 09 step 2).
//!
//! Every router gets a whole-request timeout, a request-body deadline and an
//! explicit body-size limit. A request past its timeout is dropped — for
//! `/mcp` that is the same path as a client disconnect (target query
//! cancelled, audit row `cancelled`) — and answered `504`. A body that has not
//! fully arrived by the deadline fails extraction, which frees the
//! concurrency permit a slow-loris sender would otherwise pin.

use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use tower_http::timeout::{RequestBodyDeadlineLayer, TimeoutLayer};

use crate::audit::AUDIT_WRITE_TIMEOUT;
use crate::exec::DEFAULT_STATEMENT_TIMEOUT_MS;

/// Time for a client to deliver a whole request body.
const BODY_READ_DEADLINE: Duration = Duration::from_secs(10);

/// `/mcp`: the statement ceiling, one pool acquire, the intent and outcome
/// audit writes, plus slack for authz and serialisation.
const MCP_TIMEOUT: Duration = Duration::from_millis(
    DEFAULT_STATEMENT_TIMEOUT_MS as u64
        + POOL_ACQUIRE_ALLOWANCE.as_millis() as u64
        + 2 * AUDIT_WRITE_TIMEOUT.as_millis() as u64
        + SLACK.as_millis() as u64,
);
const POOL_ACQUIRE_ALLOWANCE: Duration = Duration::from_secs(5);
const SLACK: Duration = Duration::from_secs(10);

/// OAuth / login routes: `/auth/callback` waits on the IdP code exchange,
/// which `auth::oidc` bounds at 45 s.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(60);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_timeout_outlasts_the_statement_ceiling_and_both_audit_writes() {
        let floor = Duration::from_millis(u64::from(DEFAULT_STATEMENT_TIMEOUT_MS))
            + 2 * AUDIT_WRITE_TIMEOUT;
        assert!(MCP_TIMEOUT > floor, "{MCP_TIMEOUT:?} <= {floor:?}");
    }
}
