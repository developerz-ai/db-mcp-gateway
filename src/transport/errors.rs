//! Transport-layer wiring errors.
//!
//! These surface at boot — `main` propagates the `?` and the process exits
//! before binding the listener (spec 08: refuse to come up half-loaded).

use thiserror::Error;

/// Failures that prevent the axum router from being built.
#[derive(Debug, Error)]
pub enum TransportError {
    /// A concurrency cap of zero would shed every request.
    #[error("max_concurrent_requests and max_concurrent_per_identity must be at least 1")]
    ZeroConcurrencyCap,
}
