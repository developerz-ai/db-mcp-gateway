//! TLS termination + SIGHUP hot-reload.
//!
//! Wraps `axum_server::tls_rustls::RustlsConfig` with the two operations the
//! gateway actually needs: load from on-disk PEM at boot, reload from the
//! same paths on SIGHUP. Issue #12 + spec 09 §"TLS is the default".
//!
//! The reload path mutates the shared `RustlsConfig` in place:
//! - existing TLS sessions keep their previous certificate until they close
//!   (rustls reads the certificate snapshot at handshake time, not per record)
//! - subsequent handshakes see the new certificate
//!
//! That's the cert-manager rotation contract: never drop a live connection.

use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;

/// Install the process-wide rustls `CryptoProvider`. Rustls 0.23 requires
/// exactly one provider to be selected before any TLS handshake; axum-server
/// transitively pulls in both `aws-lc-rs` and `ring`, so neither is the
/// implicit default. Idempotent — second/concurrent installs are no-ops, so
/// tests can call this freely.
pub fn install_crypto_provider() {
    // `install_default` returns Err if a provider was already installed by
    // someone else (e.g. sqlx-rustls in another binary). Either way the rest
    // of the process gets a working provider, so drop the result.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Errors from the load + reload paths. The path is folded into the Display
/// so structured logs can grep on `tls_cert_path=` without walking sources.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("failed to load TLS material from cert={cert} key={key}: {source}")]
    Load {
        cert: PathBuf,
        key: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Read cert + key off disk and build a `RustlsConfig` suitable for
/// `axum_server::bind_rustls`. Both paths must already exist — boot config
/// validation enforces that; we still surface I/O errors as typed errors so
/// `main` can `?` cleanly.
pub async fn load(cert: &Path, key: &Path) -> Result<RustlsConfig, TlsError> {
    RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|source| TlsError::Load {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            source,
        })
}

/// SIGHUP hot-reload. Mutates `config` in place so every clone (including the
/// one inside the running axum-server) sees the new cert without a restart.
///
/// On failure we leave the OLD cert in place — a malformed swap (half-written
/// PEM, wrong permissions after a sealed-secret refresh, etc.) must never
/// take the gateway down. The caller logs the error; the next SIGHUP retries.
pub async fn reload(config: &RustlsConfig, cert: &Path, key: &Path) -> Result<(), TlsError> {
    config
        .reload_from_pem_file(cert, key)
        .await
        .map_err(|source| TlsError::Load {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            source,
        })
}
