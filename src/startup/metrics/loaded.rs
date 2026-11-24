//! Gauges that say what the process loaded: the build, the config file, the
//! TLS certificate. All held ([`super::held`]) — each changes only on boot or
//! a reload.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::cert;
use super::held::{held, unix_now_secs};

/// Hex digits of the config hash label: enough to tell two configs apart,
/// short enough to read on a dashboard.
const HASH_BYTES: usize = 6;

/// `build_info{version,git_sha}`. `GIT_SHA` is read at compile time; a build
/// without it says `unknown`.
pub(crate) fn record_build_info() {
    let git_sha = option_env!("GIT_SHA").unwrap_or("unknown");
    held().set_info(
        "build_info",
        vec![
            ("version", env!("CARGO_PKG_VERSION").to_owned()),
            ("git_sha", git_sha.to_owned()),
        ],
    );
}

/// After a successful boot load or reload of `path`: the reload timestamp and
/// `config_info{hash}`. The hash is of the file as read now — the bytes on
/// disk, `${…}` references unresolved, so no resolved secret enters it.
pub(crate) async fn record_config_loaded(path: &Path) {
    held().set(
        "config_reload_last_success_timestamp",
        Vec::new(),
        unix_now_secs(),
    );
    match tokio::fs::read(path).await {
        Ok(bytes) => held().set_info("config_info", vec![("hash", short_hash(&bytes))]),
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "config re-read for its hash failed");
        }
    }
}

/// After the served certificate was (re)loaded from `cert_path`. A
/// certificate this cannot parse leaves the gauge as it was: rustls accepted
/// it, so serving is unaffected.
pub(crate) async fn record_cert_loaded(cert_path: &Path) {
    match cert::not_after(cert_path).await {
        Ok(not_after) => held().set("tls_cert_not_after_timestamp", Vec::new(), not_after as f64),
        Err(error) => tracing::warn!(
            %error,
            cert_path = %cert_path.display(),
            "TLS certificate expiry unreadable; tls_cert_not_after_timestamp not updated"
        ),
    }
}

fn short_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .take(HASH_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::short_hash;

    #[test]
    fn config_hash_is_a_short_stable_hex_prefix() {
        let hash = short_hash(b"servers: []\n");
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, short_hash(b"servers: []\n"));
        assert_ne!(hash, short_hash(b"servers: [] \n"));
    }
}
