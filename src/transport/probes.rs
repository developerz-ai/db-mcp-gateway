//! Operational endpoints: `/healthz`, `/readyz`, `/metrics`.
//!
//! Mounted on the open router — k8s probes and Prometheus scrapers don't carry
//! a bearer. None of these return DB credentials, role names, or session data.
//! See spec 09-deployment.md.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use super::app_state::AppState;

/// Prometheus text exposition content type. Version 0.0.4 is what every
/// scraper since prom 0.x understands; OpenMetrics is a superset they accept
/// when sent as text/plain.
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Cap how long a `SELECT 1` is allowed to take before /readyz gives up and
/// returns 503. Probes fire on a fast cadence; a slow DB shouldn't wedge them.
const READYZ_DB_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared shutdown flag. Flipped by the graceful-shutdown handler so that
/// probes return 503 while axum drains in-flight requests — k8s removes the
/// pod from the Service endpoint set before the pod actually exits.
#[derive(Clone, Debug, Default)]
pub struct ShutdownFlag(Arc<AtomicBool>);

impl ShutdownFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trigger(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Liveness: did the process come up and is it still running? k8s restarts
/// the container on a non-200, so this stays 200 even when the DB is down —
/// flapping liveness on transient DB outages would just thrash the pod.
pub async fn healthz(State(state): State<AppState>) -> Response {
    if state.shutdown.is_set() {
        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

/// Readiness: can we serve traffic right now? 503 during shutdown or when the
/// state DB is unreachable — k8s yanks the pod out of the Service endpoint set
/// on a 503 without restarting it.
pub async fn readyz(State(state): State<AppState>) -> Response {
    if state.shutdown.is_set() {
        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down").into_response();
    }
    let Some(pool) = state.state_db.as_ref() else {
        // No state DB wired = test bootstrap. Anything talking to /readyz in
        // that mode is a test asserting the not-ready path.
        return (StatusCode::SERVICE_UNAVAILABLE, "state db not configured").into_response();
    };
    match probe_state_db(pool).await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(()) => (StatusCode::SERVICE_UNAVAILABLE, "state db unreachable").into_response(),
    }
}

async fn probe_state_db(pool: &PgPool) -> Result<(), ()> {
    let probe = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool);
    match tokio::time::timeout(READYZ_DB_TIMEOUT, probe).await {
        Ok(Ok(_)) => Ok(()),
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

/// Prometheus scrape endpoint. Renders the global recorder.
///
/// Test bootstraps don't install the recorder (it's a process-wide singleton),
/// so a missing handle returns an empty body rather than 500 — there's
/// genuinely nothing to render.
pub async fn metrics(State(state): State<AppState>) -> Response {
    let body = state
        .metrics
        .as_ref()
        .map(PrometheusHandle::render)
        .unwrap_or_default();
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROM_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

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
        let app = router_with_state(AppState::for_tests());
        let response = app.oneshot(get_request("/healthz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "ok");
    }

    #[tokio::test]
    async fn healthz_returns_503_during_shutdown() {
        let state = AppState::for_tests();
        state.shutdown.trigger();
        let app = router_with_state(state);
        let response = app.oneshot(get_request("/healthz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// No state DB → not ready. Mirrors the boot-window state where the pod is
    /// up but hasn't connected to Postgres yet.
    #[tokio::test]
    async fn readyz_returns_503_without_state_db() {
        let app = router_with_state(AppState::for_tests());
        let response = app.oneshot(get_request("/readyz")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The probe path must not leak DB internals on failure. Cover the
    /// boot-window error body — the body must stay generic, no driver name,
    /// no role name, no host.
    #[tokio::test]
    async fn readyz_error_body_does_not_leak_internals() {
        let app = router_with_state(AppState::for_tests());
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
