//! Gauges that say what the process loaded: the build, the config file, the
//! TLS certificate. All held ([`super::held`]) — each changes only on boot or
//! a reload.

use std::path::Path;

use serde_json::Value;
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

/// `process_start_time_seconds`: when this process booted.
pub(crate) fn record_process_start() {
    held().set("process_start_time_seconds", Vec::new(), unix_now_secs());
}

/// Keys whose value is a credential or a reference to one (every
/// `Password`-typed field of the schema). Dropped before hashing: a literal
/// password in the YAML would otherwise make the label a fingerprint a
/// metrics reader could test guesses against.
const CREDENTIAL_KEYS: &[&str] = &["password", "write_password", "token", "tokens"];

/// After a successful boot load or reload of `path`: the reload timestamp and
/// `config_info{hash}`. The hash is of the file as read now, parsed, with
/// every credential field removed — so a credential-only change (a rotation)
/// leaves it as it was.
pub(crate) async fn record_config_loaded(path: &Path) {
    held().set(
        "config_reload_last_success_timestamp",
        Vec::new(),
        unix_now_secs(),
    );
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "config re-read for its hash failed");
            return;
        }
    };
    match credential_free_hash(&bytes) {
        Some(hash) => held().set_info("config_info", vec![("hash", hash)]),
        // The parse error is not logged: its text can quote the file.
        None => tracing::warn!(path = %path.display(), "config re-read for its hash did not parse"),
    }
}

fn credential_free_hash(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut config: Value = serde_saphyr::from_str_with_options(
        text,
        db_mcp_gateway::config::yaml::non_leaking_options(),
    )
    .ok()?;
    drop_credentials(&mut config);
    serde_json::to_vec(&config)
        .ok()
        .map(|canonical| short_hash(&canonical))
}

fn drop_credentials(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| !CREDENTIAL_KEYS.contains(&key.as_str()));
            map.values_mut().for_each(drop_credentials);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_credentials),
        _ => {}
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
    use super::{credential_free_hash, short_hash};

    const YAML: &str = "servers:
  - name: prod
    kind: postgres
    host: db.internal
    password: server-default
    databases:
      - { name: app, role: ro, password: hunter2, write_role: rw, write_password: s3cret }
service_accounts:
  - { name: bot, group: g, token: dbmcp_svc_abc }
  - { name: bot2, group: g, tokens: [dbmcp_svc_one, dbmcp_svc_two] }
permissions: []
";

    #[test]
    fn config_hash_ignores_every_credential_field() {
        let hash = credential_free_hash(YAML.as_bytes()).unwrap();
        for (secret, other) in [
            ("server-default", "x1"),
            ("hunter2", "x2"),
            ("s3cret", "x3"),
            ("dbmcp_svc_abc", "x4"),
            ("dbmcp_svc_two", "x5"),
        ] {
            let changed = YAML.replace(secret, other);
            assert_eq!(
                credential_free_hash(changed.as_bytes()).unwrap(),
                hash,
                "{secret}"
            );
        }
        let renamed = YAML.replace("host: db.internal", "host: db2.internal");
        assert_ne!(credential_free_hash(renamed.as_bytes()).unwrap(), hash);
    }

    #[test]
    fn config_hash_is_a_short_stable_hex_prefix() {
        let hash = short_hash(b"servers: []\n");
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, short_hash(b"servers: []\n"));
        assert_ne!(hash, short_hash(b"servers: [] \n"));
    }
}
