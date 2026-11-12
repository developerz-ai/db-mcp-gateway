//! `ConfigError`: every way an env-driven runtime knob can be rejected at boot.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid GATEWAY_BIND `{value}`: {source}")]
    Bind {
        value: String,
        source: std::net::AddrParseError,
    },
    #[error("invalid METRICS_BIND `{value}`: {source}")]
    MetricsBind {
        value: String,
        source: std::net::AddrParseError,
    },
    #[error(
        "METRICS_BIND and GATEWAY_BIND are both `{0}`: `/metrics` must not share the public listener"
    )]
    MetricsBindCollides(std::net::SocketAddr),
    #[error("invalid MCP_PATH `{0}`: must be a non-empty absolute path (e.g. `/mcp`)")]
    McpPath(String),
    #[error(
        "invalid MCP_PATH `{0}`: that path is already served by the gateway \
         (probes, OAuth, discovery metadata, or the admin API). Pick another, e.g. `/mcp`"
    )]
    McpPathReserved(String),
    #[error("invalid STATE_DB_POOL_SIZE `{value}`: {source}")]
    StateDbPoolSize {
        value: String,
        source: std::num::ParseIntError,
    },
    #[error(
        "invalid STATE_DB_POOL_SIZE `0`: the state DB pool needs at least one connection — \
         every session lookup and audit write would time out"
    )]
    StateDbPoolSizeZero,
    #[error(
        "invalid STATE_DB_POOL_SIZE `{size}`: larger than the {max_concurrent_requests} \
         concurrent-request ceiling, so the extra connections can never be used"
    )]
    StateDbPoolSizeAboveConcurrency {
        size: u32,
        max_concurrent_requests: usize,
    },
    #[error("invalid {name} `{value}`: must be a positive integer (0 would shed every request)")]
    ConcurrencyCap { name: &'static str, value: String },
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
    #[error("invalid PERMISSIONS_CACHE_TTL_SECONDS `{0}`: at most 300 seconds")]
    PermissionsCacheTtlTooLong(u64),
    #[error("invalid SESSION_CACHE_TTL_SECONDS `{value}`: {source}")]
    SessionCacheTtl {
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
