//! Bootstrap configuration for the gateway.
//!
//! Deliberately minimal: only what the transport scaffold (issue #1) needs to
//! bind and mount its endpoint. The full YAML schema, secrets resolution, hot
//! reload, and validation land with issue #16.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Path the MCP endpoint is mounted at (e.g. `/mcp`).
    pub mcp_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443)),
            mcp_path: "/mcp".to_string(),
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
}

impl Config {
    /// Build config from environment, falling back to defaults.
    ///
    /// `GATEWAY_BIND` (e.g. `0.0.0.0:8443`) and `MCP_PATH` (e.g. `/mcp`) override
    /// the defaults. A malformed `GATEWAY_BIND` is a startup error, not a silent
    /// fallback — config mistakes should fail at boot.
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
}
