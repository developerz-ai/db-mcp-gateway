//! `CliError`: why a CLI command could not finish, and its exit code.

use reqwest::StatusCode;

use super::{EXIT_ERROR, EXIT_FAILED};

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("could not {what}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    /// The request never got an HTTP answer. The URL is the gateway's own,
    /// never one carrying a credential.
    #[error("could not reach {url}: {reason}")]
    Unreachable { url: String, reason: String },
    /// The gateway answered with an error. `code` and `message` come from its
    /// credential-free error body.
    #[error("{what}: HTTP {status} {code}: {message}")]
    Refused {
        what: String,
        status: StatusCode,
        code: String,
        message: String,
    },
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Config(#[from] db_mcp_gateway::config::ConfigLoadError),
    #[error(transparent)]
    ConfigFile(#[from] db_mcp_gateway::config::ConfigFileError),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Refused { .. } | Self::Invalid(_) | Self::Config(_) | Self::ConfigFile(_) => {
                EXIT_FAILED
            }
            Self::Io { .. } | Self::Unreachable { .. } => EXIT_ERROR,
        }
    }

    pub fn io(what: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            what: what.into(),
            source,
        }
    }

    /// `reqwest`'s `Display` can include the full URL with its query; only
    /// the error's class and our own base URL are kept.
    pub fn unreachable(url: &str, err: &reqwest::Error) -> Self {
        let reason = if err.is_timeout() {
            "timed out"
        } else if err.is_connect() {
            "connection failed"
        } else if err.is_decode() {
            "unreadable response body"
        } else {
            "request failed"
        };
        Self::Unreachable {
            url: url.to_string(),
            reason: reason.to_string(),
        }
    }
}
