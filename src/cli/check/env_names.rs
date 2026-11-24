//! The environment variables the gateway reads — the table in
//! website/docs/deployment/quickstart.md §"The environment variables the
//! gateway reads", which `tests/doc_drift.rs` pins to the code. A unit test
//! pins this list to that table.

pub const KNOWN_ENV: &[&str] = &[
    "DB_MCP_GATEWAY_CONFIG",
    "STATE_DB_URL",
    "PERMISSIONS_DB_DSN",
    "GATEWAY_BIND",
    "MCP_ALLOWED_ORIGINS",
    "TRUSTED_PROXIES",
    "MCP_PATH",
    "METRICS_BIND",
    "MAX_CONCURRENT_REQUESTS",
    "MAX_CONCURRENT_PER_IDENTITY",
    "STATE_DB_POOL_SIZE",
    "STATE_DB_CONNECT_TIMEOUT_SECONDS",
    "OIDC_ISSUER",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "OIDC_AUDIENCE",
    "OIDC_REDIRECT_URL",
    "OIDC_GROUPS_CLAIM",
    "OIDC_SCOPES",
    "OIDC_GROUPS_PREFIX",
    "OIDC_TOKEN_AUTH_METHOD",
    "GROUPS_MAX_AGE",
    "GATEWAY_SUPPORT_CONTACT",
    "SESSION_SIGNING_KEY",
    "ALLOW_INSECURE_SIGNING_KEY",
    "SESSION_TTL_HOURS",
    "REFRESH_TTL_DAYS",
    "TLS_CERT_PATH",
    "TLS_KEY_PATH",
    "TLS_DISABLED",
    "AUDIT_RETENTION_DAYS",
    "PERMISSIONS_CACHE_TTL_SECONDS",
    "SESSION_CACHE_TTL_SECONDS",
    "PG_CANCEL_POOL_SIZE",
    "SENTRY_DSN",
    "SENTRY_ENVIRONMENT",
    "RUST_LOG",
];

/// Prefixes only the gateway's own variables use. `RUST_` and `SENTRY_` are
/// left out: the toolchain and the Sentry SDK read variables of their own.
pub const GATEWAY_ENV_PREFIXES: &[&str] = &[
    "DB_MCP_GATEWAY_",
    "STATE_DB_",
    "PERMISSIONS_",
    "GATEWAY_",
    "MCP_",
    "METRICS_",
    "MAX_CONCURRENT_",
    "OIDC_",
    "GROUPS_",
    "SESSION_",
    "REFRESH_",
    "TLS_",
    "AUDIT_",
    "PG_CANCEL_",
];
