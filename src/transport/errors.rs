//! Transport-layer wiring errors (#52).
//!
//! These surface at boot — `main` propagates the `?` and the process exits
//! before binding the listener. The contract matches the spec 08 rule:
//! refuse to come up half-loaded; never serve traffic against an invalid
//! runtime state. Keep variants narrow so an operator reading the log line
//! can act on it (set the missing config, fix the wiring) without spelunking
//! the source.

use thiserror::Error;

/// Failures that prevent the axum router from being built.
#[derive(Debug, Error)]
pub enum TransportError {
    /// `admin.enabled = true` in YAML but `AppState` didn't ship the
    /// dependencies `/admin/v1/*` requires. Previously this was a silent
    /// 404 surface — masking the wiring regression. Now we refuse to start.
    #[error(
        "admin.enabled is true but required dependencies are missing: \
         {missing} (check that AppState carries permissions_repo and state_db)"
    )]
    AdminDepsMissing { missing: &'static str },
}
