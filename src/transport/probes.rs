//! Operational endpoints: `/healthz`, `/readyz`.
//!
//! Mounted on the open router — k8s probes don't carry a bearer. Neither
//! returns DB credentials, role names, or session data. `/metrics` is served
//! on its own listener (`METRICS_BIND`), not here. See spec 09-deployment.md.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::PgPool;
use sqlx::pool::PoolConnection;
use sqlx::postgres::Postgres;
use tokio::sync::Mutex;

use super::app_state::AppState;

/// Cap how long a `SELECT 1` is allowed to take before /readyz gives up and
/// returns 503. Probes fire on a fast cadence; a slow DB shouldn't wedge them.
const READYZ_DB_TIMEOUT: Duration = Duration::from_secs(2);

/// How long one state-DB probe answers `/readyz`. Probes are unauthenticated
/// and uncapped, so without this every probe (or a flood posing as one) would
/// take a state-DB connection.
const READYZ_CACHE_TTL: Duration = Duration::from_secs(1);

/// The last state-DB probe result and when it ran, plus a gate so at most one
/// probe runs at a time.
#[derive(Clone, Debug, Default)]
pub struct ReadinessCache {
    last: Arc<ArcSwapOption<(Instant, bool)>>,
    probing: Arc<Mutex<()>>,
}

impl ReadinessCache {
    /// Never queues: while one probe runs, concurrent callers get the last
    /// result (not ready if there is none yet) instead of waiting on it.
    async fn state_db_ready(&self, pool: &PgPool) -> bool {
        let cached = self.last.load_full();
        if let Some((at, ready)) = cached.as_deref().copied()
            && at.elapsed() < READYZ_CACHE_TTL
        {
            return ready;
        }
        let Ok(_probing) = self.probing.try_lock() else {
            return cached.is_some_and(|last| last.1);
        };
        let ready = probe_state_db(pool).await.is_ok();
        self.last.store(Some(Arc::new((Instant::now(), ready))));
        ready
    }
}

/// Liveness: did the process come up and is it still running? k8s restarts
/// the container on a non-200, so this stays 200 even when the DB is down —
/// flapping liveness on transient DB outages would just thrash the pod.
pub async fn healthz(State(state): State<AppState>) -> Response {
    if state.shutdown.is_cancelled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

/// Readiness: can we serve traffic right now? 503 during shutdown or when the
/// state DB is unreachable — k8s yanks the pod out of the Service endpoint set
/// on a 503 without restarting it.
pub async fn readyz(State(state): State<AppState>) -> Response {
    if state.shutdown.is_cancelled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down").into_response();
    }
    if state.readiness.state_db_ready(&state.mcp.state_db).await {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "state db unreachable").into_response()
    }
}

/// `SELECT 1` on a connection taken without queueing behind request traffic.
/// A pool at its size limit with no idle connection is busy serving queries,
/// which proves the database is up — that counts as ready, not as a failure.
async fn probe_state_db(pool: &PgPool) -> Result<(), ()> {
    let probe = async {
        let mut conn: PoolConnection<Postgres> = match pool.try_acquire() {
            Some(conn) => conn,
            None if pool.size() >= pool.options().get_max_connections() => return Ok(()),
            None => pool.acquire().await?,
        };
        crate::state::ping(&mut conn).await
    };
    match tokio::time::timeout(READYZ_DB_TIMEOUT, probe).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            // Body stays generic on purpose — the error may contain a host
            // or role name; spec 05 forbids leaking either via HTTP.
            tracing::warn!(%err, "readyz: state db query failed");
            Err(())
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_secs = READYZ_DB_TIMEOUT.as_secs(),
                "readyz: state db probe timed out"
            );
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    use crate::transport::app_state::offline_for_tests;

    /// Bodies in these tests are short fixed strings; an 8KiB cap is more than
    /// the real responses ever produce.
    const MAX_BODY_BYTES: usize = 8 * 1024;

    fn router_with_state(state: AppState) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .with_state(state)
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn get_request(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_ok_when_live() {
        let app = router_with_state(offline_for_tests());
        let response = app.oneshot(get_request("/healthz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "ok");
    }

    #[tokio::test]
    async fn healthz_returns_503_during_shutdown() {
        let state = offline_for_tests();
        state.shutdown.cancel();
        let app = router_with_state(state);
        let response = app.oneshot(get_request("/healthz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Unreachable state DB → not ready. Mirrors the boot-window state where
    /// the pod is up but hasn't connected to Postgres yet.
    #[tokio::test]
    async fn readyz_returns_503_without_state_db() {
        let app = router_with_state(offline_for_tests());
        let response = app.oneshot(get_request("/readyz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A fresh cached result answers `/readyz` without touching the (here
    /// unreachable) state DB.
    #[tokio::test]
    async fn readyz_answers_from_a_fresh_cached_probe() {
        let state = offline_for_tests();
        state
            .readiness
            .last
            .store(Some(Arc::new((Instant::now(), true))));
        let app = router_with_state(state);
        let response = app.oneshot(get_request("/readyz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The probe path must not leak DB internals on failure. Cover the
    /// boot-window error body — the body must stay generic, no driver name,
    /// no role name, no host.
    #[tokio::test]
    async fn readyz_error_body_does_not_leak_internals() {
        let app = router_with_state(offline_for_tests());
        let response = app.oneshot(get_request("/readyz")).await.unwrap();
        let body = body_text(response).await;
        assert!(
            !body.contains("postgres"),
            "body leaked driver name: {body}"
        );
        assert!(
            !body.contains("password"),
            "body leaked password word: {body}"
        );
    }
}
