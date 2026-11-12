//! Env-driven runtime knobs: bind address, MCP path, state DB, TLS, cache TTLs.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU32;
use std::path::PathBuf;

pub use error::ConfigError;
use mcp_path::validate_mcp_path;

mod error;
mod mcp_path;

const DEFAULT_STATE_DB_URL: &str = "postgres://gateway:gateway-dev-only@localhost:5433/gateway";
// Evaluated at compile time: a zero literal fails the build, never the process.
const DEFAULT_STATE_DB_POOL_SIZE: NonZeroU32 = NonZeroU32::new(10).expect("non-zero literal");
/// Loopback by default: `/metrics` is not part of the public surface. A
/// cluster scrape sets `METRICS_BIND=0.0.0.0:9090` and fences the port with a
/// NetworkPolicy.
const DEFAULT_METRICS_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090));
/// Spec 07 §Storage: "Hot — Gateway's state Postgres — 90 days (configurable)".
const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 90;
/// Spec 12 §Cache: per-user DB-grant cache TTL. 60s keeps the request path off
/// the state DB while bounding the window in which a revoked-but-not-yet-
/// invalidated grant could still be honored. Admin API writes (#52–#54) call
/// `PermissionsCache::invalidate` directly so the practical staleness is the
/// in-flight request, not the TTL.
const DEFAULT_PERMISSIONS_CACHE_TTL_SECONDS: u64 = 60;
const MAX_PERMISSIONS_CACHE_TTL_SECONDS: u64 = 300;
/// A3: freshness TTL for the in-memory session cache. A cache hit older than
/// this re-reads the state DB, so a session revoked on another replica stops
/// being honored within this window. Short — revocation is security-critical.
/// `0` re-validates every request. Kept in sync with the test-facing default
/// in `auth::session_cache`; this value is the operator override.
const DEFAULT_SESSION_CACHE_TTL_SECONDS: u64 = 30;
/// Default `MAX_CONCURRENT_REQUESTS`: process-wide in-flight ceiling.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 512;
/// Default `MAX_CONCURRENT_PER_IDENTITY`: one caller's in-flight ceiling.
pub const DEFAULT_MAX_CONCURRENT_PER_IDENTITY: usize = 16;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Address the Prometheus `/metrics` listener binds to — a separate
    /// listener so the scrape endpoint never rides the public one.
    pub metrics_bind: SocketAddr,
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
    /// Freshness TTL (seconds) for the session cache (A3). Bounds cross-replica
    /// revocation staleness; `0` re-validates every request.
    pub session_cache_ttl_seconds: u64,
    /// Process-wide ceiling on concurrent in-flight gated requests
    /// (`MAX_CONCURRENT_REQUESTS`; past it, 503).
    pub max_concurrent_requests: usize,
    /// Per-identity ceiling on concurrent in-flight gated requests
    /// (`MAX_CONCURRENT_PER_IDENTITY`; past it, 429).
    pub max_concurrent_per_identity: usize,
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
    /// Dev-only. Boot emits a loud warning once.
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
    /// Request-path pool size. Zero is unrepresentable: a zero-connection
    /// pool times out every acquire.
    pub pool_size: NonZeroU32,
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
            metrics_bind: DEFAULT_METRICS_BIND,
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
            session_cache_ttl_seconds: DEFAULT_SESSION_CACHE_TTL_SECONDS,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            max_concurrent_per_identity: DEFAULT_MAX_CONCURRENT_PER_IDENTITY,
        }
    }
}

impl Config {
    /// Build config from environment, falling back to defaults.
    ///
    /// `GATEWAY_BIND`, `METRICS_BIND`, `MCP_PATH`, `STATE_DB_URL`, and
    /// `STATE_DB_POOL_SIZE` override the defaults. Malformed values are startup
    /// errors — config mistakes should fail at boot, not silently.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Config::default();

        if let Ok(value) = std::env::var("GATEWAY_BIND") {
            config.bind = value
                .parse()
                .map_err(|source| ConfigError::Bind { value, source })?;
        }
        if let Ok(value) = std::env::var("METRICS_BIND") {
            config.metrics_bind = value
                .parse()
                .map_err(|source| ConfigError::MetricsBind { value, source })?;
        }
        if config.metrics_bind == config.bind {
            return Err(ConfigError::MetricsBindCollides(config.bind));
        }
        if let Ok(path) = std::env::var("MCP_PATH") {
            config.mcp_path = validate_mcp_path(path)?;
        }
        if let Ok(url) = std::env::var("STATE_DB_URL") {
            config.state_db.url = url;
        }
        // Read before STATE_DB_POOL_SIZE, which is bounded by the global cap.
        if let Ok(value) = std::env::var("MAX_CONCURRENT_REQUESTS") {
            config.max_concurrent_requests = parse_cap("MAX_CONCURRENT_REQUESTS", value)?;
        }
        if let Ok(value) = std::env::var("MAX_CONCURRENT_PER_IDENTITY") {
            config.max_concurrent_per_identity = parse_cap("MAX_CONCURRENT_PER_IDENTITY", value)?;
        }
        if let Ok(value) = std::env::var("STATE_DB_POOL_SIZE") {
            config.state_db.pool_size = parse_pool_size(value, config.max_concurrent_requests)?;
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
            config.permissions_cache_ttl_seconds = parse_cache_ttl(value)?;
        }
        // 0 is valid here — it means "re-validate every request" (no caching).
        if let Ok(value) = std::env::var("SESSION_CACHE_TTL_SECONDS") {
            config.session_cache_ttl_seconds =
                value
                    .parse()
                    .map_err(|source| ConfigError::SessionCacheTtl {
                        value: value.clone(),
                        source,
                    })?;
        }

        config.tls = tls_from_env()?;

        Ok(config)
    }
}

/// The grant cache bounds how long a revoked grant can still be honoured on a
/// replica that missed the invalidation; past five minutes that window is an
/// outage of revocation, so a larger value fails boot rather than being
/// silently clamped.
fn parse_cache_ttl(value: String) -> Result<u64, ConfigError> {
    let ttl: u64 = value
        .parse()
        .map_err(|source| ConfigError::PermissionsCacheTtl {
            value: value.clone(),
            source,
        })?;
    if ttl > MAX_PERMISSIONS_CACHE_TTL_SECONDS {
        return Err(ConfigError::PermissionsCacheTtlTooLong(ttl));
    }
    Ok(ttl)
}

/// A concurrency ceiling: a positive integer. Zero would shed every request.
fn parse_cap(name: &'static str, value: String) -> Result<usize, ConfigError> {
    match value.trim().parse::<usize>() {
        Ok(0) | Err(_) => Err(ConfigError::ConcurrencyCap { name, value }),
        Ok(cap) => Ok(cap),
    }
}

/// `STATE_DB_POOL_SIZE`: non-zero, and no larger than the request ceiling —
/// connections past `max_concurrent_requests` can never be checked out at
/// once, they only hold server slots.
fn parse_pool_size(
    value: String,
    max_concurrent_requests: usize,
) -> Result<NonZeroU32, ConfigError> {
    let parsed: u32 = value
        .parse()
        .map_err(|source| ConfigError::StateDbPoolSize {
            value: value.clone(),
            source,
        })?;
    let Some(size) = NonZeroU32::new(parsed) else {
        return Err(ConfigError::StateDbPoolSizeZero);
    };
    if usize::try_from(parsed).is_ok_and(|n| n > max_concurrent_requests) {
        return Err(ConfigError::StateDbPoolSizeAboveConcurrency {
            size: parsed,
            max_concurrent_requests,
        });
    }
    Ok(size)
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

#[cfg(test)]
mod tests;
