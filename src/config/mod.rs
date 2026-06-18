//! Bootstrap configuration for the gateway.
//!
//! Two-layered today:
//! - `Config` (this file) carries env-driven runtime knobs: bind address,
//!   MCP path, state DB pool — what we needed for #1 and #2.
//! - `ConfigFile` (`yaml`) carries the operator's YAML: `servers:` +
//!   `permissions:` — what we need for #3.
//!
//! Unification of both into a single YAML lands with issue #16.

pub mod schema;
pub mod secret;
pub mod yaml;

pub use schema::{Action, Constraints, Database, Grant, Permission, Server, ServerKind, Tls};
pub use secret::{Password, SecretError};
pub use yaml::{
    AdminBlock, ConfigFile, ConfigFileError, ConfigLoadError, PermissionsStoreBlock,
    PermissionsStoreDriver,
};

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

const DEFAULT_STATE_DB_URL: &str = "postgres://gateway:gateway-dev-only@localhost:5433/gateway";
const DEFAULT_STATE_DB_POOL_SIZE: u32 = 10;
/// Spec 07 §Storage: "Hot — Gateway's state Postgres — 90 days (configurable)".
const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 90;
/// Spec 12 §Cache: per-user DB-grant cache TTL. 60s keeps the request path off
/// the state DB while bounding the window in which a revoked-but-not-yet-
/// invalidated grant could still be honored. Admin API writes (#52–#54) call
/// `PermissionsCache::invalidate` directly so the practical staleness is the
/// in-flight request, not the TTL.
const DEFAULT_PERMISSIONS_CACHE_TTL_SECONDS: u64 = 60;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Path the MCP endpoint is mounted at (e.g. `/mcp`).
    pub mcp_path: String,
    /// The gateway's own Postgres (sessions, audit, denylist).
    pub state_db: StateDbConfig,
    /// Days to keep audit rows in hot storage before the pruner deletes
    /// them. Archive sink (when added) would take rows out before delete;
    /// without archive, this is the hard retention period.
    pub audit_retention_days: u32,
    /// TLS termination at the gateway. `Enabled` carries the on-disk paths
    /// the boot path reads and the SIGHUP handler reloads. `Disabled` is the
    /// dev-only escape — when set, the gateway serves plain HTTP.
    pub tls: TlsConfig,
    /// Per-user TTL for the DB-grant resolver cache (#49).
    pub permissions_cache_ttl_seconds: u64,
}

/// TLS state — present-and-on or explicitly-off-for-dev. Modeled as an enum
/// (not `Option<paths> + bool`) so the boot path can't accidentally serve
/// plain HTTP because the cert paths happened to be empty. Spec 12-#12: TLS
/// is the default; plain HTTP requires an explicit opt-out.
#[derive(Debug, Clone)]
pub enum TlsConfig {
    Enabled {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Dev-only. Boot emits a loud warning every minute.
    Disabled,
}

impl TlsConfig {
    pub fn is_enabled(&self) -> bool {
        matches!(self, TlsConfig::Enabled { .. })
    }
}

/// `Debug` is hand-rolled to redact `url`, which carries the Postgres password.
#[derive(Clone)]
pub struct StateDbConfig {
    pub url: String,
    pub pool_size: u32,
}

impl std::fmt::Debug for StateDbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateDbConfig")
            .field("url", &"<redacted>")
            .field("pool_size", &self.pool_size)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443)),
            mcp_path: "/mcp".to_string(),
            state_db: StateDbConfig {
                url: DEFAULT_STATE_DB_URL.to_string(),
                pool_size: DEFAULT_STATE_DB_POOL_SIZE,
            },
            audit_retention_days: DEFAULT_AUDIT_RETENTION_DAYS,
            // No safe default for TLS exists at this layer — `from_env` resolves
            // the real value, refusing to boot if the operator didn't supply
            // cert+key or didn't explicitly opt out. `Default` is only used by
            // tests and `for_tests`; both run plain HTTP.
            tls: TlsConfig::Disabled,
            permissions_cache_ttl_seconds: DEFAULT_PERMISSIONS_CACHE_TTL_SECONDS,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid GATEWAY_BIND `{value}`: {source}")]
    Bind {
        value: String,
        source: std::net::AddrParseError,
    },
    #[error("invalid MCP_PATH `{0}`: must be a non-empty absolute path (e.g. `/mcp`)")]
    McpPath(String),
    #[error("invalid STATE_DB_POOL_SIZE `{value}`: {source}")]
    StateDbPoolSize {
        value: String,
        source: std::num::ParseIntError,
    },
    #[error("invalid AUDIT_RETENTION_DAYS `{value}`: {source}")]
    AuditRetentionDays {
        value: String,
        source: std::num::ParseIntError,
    },
    #[error("invalid AUDIT_RETENTION_DAYS `{0}`: must be greater than zero")]
    AuditRetentionZero(String),
    #[error("invalid PERMISSIONS_CACHE_TTL_SECONDS `{value}`: {source}")]
    PermissionsCacheTtl {
        value: String,
        source: std::num::ParseIntError,
    },
    #[error(
        "TLS is required but not configured: set TLS_CERT_PATH and TLS_KEY_PATH, \
         or TLS_DISABLED=true for local dev (never in production)"
    )]
    TlsMissing,
    #[error("TLS_CERT_PATH `{path}` is not readable: {source}")]
    TlsCertUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("TLS_KEY_PATH `{path}` is not readable: {source}")]
    TlsKeyUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TLS_DISABLED `{0}`: expected `true` or `false`")]
    TlsDisabledFlag(String),
}

impl Config {
    /// Build config from environment, falling back to defaults.
    ///
    /// `GATEWAY_BIND`, `MCP_PATH`, `STATE_DB_URL`, and `STATE_DB_POOL_SIZE`
    /// override the defaults. Malformed values are startup errors — config
    /// mistakes should fail at boot, not silently.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Config::default();

        if let Ok(value) = std::env::var("GATEWAY_BIND") {
            config.bind = value
                .parse()
                .map_err(|source| ConfigError::Bind { value, source })?;
        }
        if let Ok(path) = std::env::var("MCP_PATH") {
            config.mcp_path = validate_mcp_path(path)?;
        }
        if let Ok(url) = std::env::var("STATE_DB_URL") {
            config.state_db.url = url;
        }
        if let Ok(value) = std::env::var("STATE_DB_POOL_SIZE") {
            config.state_db.pool_size = value
                .parse()
                .map_err(|source| ConfigError::StateDbPoolSize { value, source })?;
        }
        if let Ok(value) = std::env::var("AUDIT_RETENTION_DAYS") {
            let parsed: u32 = value
                .parse()
                .map_err(|source| ConfigError::AuditRetentionDays {
                    value: value.clone(),
                    source,
                })?;
            // Zero would make the pruner immediately delete every audit row
            // — a silent durability violation. Reject at boot.
            if parsed == 0 {
                return Err(ConfigError::AuditRetentionZero(value));
            }
            config.audit_retention_days = parsed;
        }
        if let Ok(value) = std::env::var("PERMISSIONS_CACHE_TTL_SECONDS") {
            config.permissions_cache_ttl_seconds =
                value
                    .parse()
                    .map_err(|source| ConfigError::PermissionsCacheTtl {
                        value: value.clone(),
                        source,
                    })?;
        }

        config.tls = tls_from_env()?;

        Ok(config)
    }
}

/// Resolve `TlsConfig` from `TLS_DISABLED` / `TLS_CERT_PATH` / `TLS_KEY_PATH`.
///
/// Refuses to boot without TLS unless `TLS_DISABLED=true` is set explicitly —
/// missing/empty cert paths are *not* an implicit opt-out (issue #12). The
/// readability check here is cheap and catches the common "sealed-secret
/// volume isn't mounted" failure before transport spins up.
fn tls_from_env() -> Result<TlsConfig, ConfigError> {
    if let Ok(raw) = std::env::var("TLS_DISABLED") {
        match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => return Ok(TlsConfig::Disabled),
            "false" | "0" | "no" | "" => {}
            _ => return Err(ConfigError::TlsDisabledFlag(raw)),
        }
    }

    let cert = std::env::var("TLS_CERT_PATH").ok().map(PathBuf::from);
    let key = std::env::var("TLS_KEY_PATH").ok().map(PathBuf::from);
    let (cert_path, key_path) = match (cert, key) {
        (Some(c), Some(k)) => (c, k),
        _ => return Err(ConfigError::TlsMissing),
    };

    std::fs::metadata(&cert_path).map_err(|source| ConfigError::TlsCertUnreadable {
        path: cert_path.clone(),
        source,
    })?;
    std::fs::metadata(&key_path).map_err(|source| ConfigError::TlsKeyUnreadable {
        path: key_path.clone(),
        source,
    })?;

    Ok(TlsConfig::Enabled {
        cert_path,
        key_path,
    })
}

fn validate_mcp_path(path: String) -> Result<String, ConfigError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with('/')
        || trimmed == "/"
        || trimmed.contains(char::is_whitespace)
    {
        return Err(ConfigError::McpPath(path));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths_are_accepted() {
        assert_eq!(validate_mcp_path("/mcp".into()).unwrap(), "/mcp");
        assert_eq!(validate_mcp_path("/v1/mcp".into()).unwrap(), "/v1/mcp");
    }

    #[test]
    fn invalid_paths_are_rejected() {
        for bad in ["", " ", "/", "mcp", "/with space", "  "] {
            assert!(
                validate_mcp_path(bad.into()).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn default_has_dev_state_db_url() {
        let config = Config::default();
        assert!(config.state_db.url.contains("localhost"));
        assert_eq!(config.state_db.pool_size, DEFAULT_STATE_DB_POOL_SIZE);
    }

    /// `AUDIT_RETENTION_DAYS=0` would let the pruner wipe every audit row on
    /// its next tick. Refuse at boot, per spec 08 "invalid config must refuse
    /// to start".
    #[test]
    fn audit_retention_zero_is_rejected() {
        // Direct unit test on the surface that consumes the value, so we don't
        // race on the process-wide env var across tests.
        let err = ConfigError::AuditRetentionZero("0".to_string());
        let rendered = format!("{err}");
        assert!(rendered.contains("must be greater than zero"), "{rendered}");
    }

    /// The TlsMissing message is operator-facing — it must spell out both env
    /// vars AND the dev-only opt-out, so the first thing a stuck operator
    /// reads in their logs already names the fix. Regression guard.
    #[test]
    fn tls_missing_error_names_the_envs_and_dev_escape() {
        let rendered = format!("{}", ConfigError::TlsMissing);
        assert!(rendered.contains("TLS_CERT_PATH"), "{rendered}");
        assert!(rendered.contains("TLS_KEY_PATH"), "{rendered}");
        assert!(rendered.contains("TLS_DISABLED"), "{rendered}");
    }
}
