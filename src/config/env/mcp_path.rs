//! `MCP_PATH` validation: reject paths the gateway already mounts.

use super::ConfigError;

/// Paths the gateway mounts itself. `mcp_path` gets both a `GET` (SSE) and a
/// `POST` handler, so overlapping any of these makes axum panic while building
/// the router — a boot crash with a router-internals message instead of a
/// config error naming the offending setting (#136). Kept in sync by hand with
/// `transport::router`; `RESERVED_MCP_PATH_PREFIXES` covers the two families
/// whose members are generated rather than listed.
const RESERVED_MCP_PATHS: &[&str] = &[
    "/healthz",
    "/readyz",
    "/metrics",
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/authorize",
    "/token",
    "/revoke",
    "/register",
];

/// Route families the gateway owns wholesale: the admin API (`/admin/v1/…`,
/// mounted only when `admin.enabled`, but reserved unconditionally so toggling
/// it can't turn a working config into a boot panic) and RFC 8414/9728
/// discovery metadata.
const RESERVED_MCP_PATH_PREFIXES: &[&str] = &["/admin", "/.well-known"];

pub(super) fn validate_mcp_path(path: String) -> Result<String, ConfigError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with('/')
        || trimmed == "/"
        || trimmed.contains(char::is_whitespace)
    {
        return Err(ConfigError::McpPath(path));
    }
    let collides = RESERVED_MCP_PATHS.contains(&trimmed)
        || RESERVED_MCP_PATH_PREFIXES
            .iter()
            .any(|prefix| trimmed == *prefix || trimmed.starts_with(&format!("{prefix}/")));
    if collides {
        return Err(ConfigError::McpPathReserved(path));
    }
    Ok(trimmed.to_string())
}
