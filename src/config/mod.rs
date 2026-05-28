//! Bootstrap configuration for the gateway.
//!
//! Deliberately minimal: only what's needed to bind, mount the MCP endpoint,
//! and reach the gateway's own Postgres. The full YAML schema, secrets
//! resolution, hot reload, and validation land with issue #16.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

const DEFAULT_STATE_DB_URL: &str =
    "postgres://gateway:gateway-dev-only@localhost:5433/gateway";
const DEFAULT_STATE_DB_POOL_SIZE: u32 = 10;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Path the MCP endpoint is mounted at (e.g. `/mcp`).
    pub mcp_path: String,
    /// The gateway's own Postgres (sessions, audit, denylist).
    pub state_db: StateDbConfig,
}

#[derive(Debug, Clone)]
pub struct StateDbConfig {
    pub url: String,
    pub pool_size: u32,
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

        Ok(config)
    }
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
}
