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
    #[error(transparent)]
    TlsDisabledFlag(#[from] super::BoolFlagError),
}

impl ConfigError {
    /// The variable this refusal is about — never its value, so `--check`
    /// can name it in CI logs.
    pub fn variable(&self) -> &'static str {
        match self {
            Self::Bind { .. } => "GATEWAY_BIND",
            Self::MetricsBind { .. } | Self::MetricsBindCollides(_) => "METRICS_BIND",
            Self::McpPath(_) | Self::McpPathReserved(_) => "MCP_PATH",
            Self::StateDbPoolSize { .. }
            | Self::StateDbPoolSizeZero
            | Self::StateDbPoolSizeAboveConcurrency { .. } => "STATE_DB_POOL_SIZE",
            Self::ConcurrencyCap { name, .. } => name,
            Self::AuditRetentionDays { .. } | Self::AuditRetentionZero(_) => "AUDIT_RETENTION_DAYS",
            Self::PermissionsCacheTtl { .. } | Self::PermissionsCacheTtlTooLong(_) => {
                "PERMISSIONS_CACHE_TTL_SECONDS"
            }
            Self::SessionCacheTtl { .. } => "SESSION_CACHE_TTL_SECONDS",
            Self::TlsMissing | Self::TlsCertUnreadable { .. } => "TLS_CERT_PATH",
            Self::TlsKeyUnreadable { .. } => "TLS_KEY_PATH",
            Self::TlsDisabledFlag(flag) => flag.var,
        }
    }

    /// A refusal about the deployment rather than a value: a required TLS
    /// setting left unset, or a cert/key file not mounted where `--check`
    /// runs (CI without the deployment's volumes).
    pub fn is_deployment_only(&self) -> bool {
        matches!(
            self,
            Self::TlsMissing | Self::TlsCertUnreadable { .. } | Self::TlsKeyUnreadable { .. }
        )
    }
}
