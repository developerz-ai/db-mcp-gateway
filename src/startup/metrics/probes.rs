//! `/healthz` and `/readyz` on the metrics listener, so kubelet probes need
//! not reach the public port (plan 101 O14). The listener binds before the
//! app state exists — a taken `METRICS_BIND` fails boot first — so the state
//! arrives later through [`attach`]; until then the process is live but not
//! ready.

use std::sync::OnceLock;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use db_mcp_gateway::transport::{AppState, probes};

/// Where the probes find the app state once boot has built it.
#[derive(Debug, Default)]
pub(crate) struct ProbeState(OnceLock<AppState>);

impl ProbeState {
    /// Set once; a second call keeps the first state.
    pub(crate) fn attach(&self, state: AppState) {
        if self.0.set(state).is_err() {
            tracing::warn!("probe state attached twice; keeping the first");
        }
    }
}

/// The process-wide probe state the metrics listener serves.
pub(crate) fn probe_state() -> &'static ProbeState {
    static STATE: ProbeState = ProbeState(OnceLock::new());
    &STATE
}

pub(super) async fn healthz(State(probe): State<&'static ProbeState>) -> Response {
    match probe.0.get() {
        Some(state) => probes::healthz(State(state.clone())).await,
        None => (StatusCode::OK, "starting").into_response(),
    }
}

pub(super) async fn readyz(State(probe): State<&'static ProbeState>) -> Response {
    match probe.0.get() {
        Some(state) => probes::readyz(State(state.clone())).await,
        None => (StatusCode::SERVICE_UNAVAILABLE, "starting").into_response(),
    }
}
