//! Auth configuration: the OIDC client identity, claim mapping, and the
//! gateway-side session JWT signing key.
//!
//! Lives in env for now; folds into the YAML schema with issue #16. Mock mode
//! exists so CI doesn't need a real IdP — see `auth::oidc::OidcClient` and
//! the in-process mock in `tests/`.

use std::time::Duration;

const DEFAULT_GROUPS_CLAIM: &str = "groups";
const DEFAULT_SESSION_TTL_HOURS: u64 = 8;
const DEFAULT_DEV_SIGNING_KEY: &str = "dev-only-session-signing-key-change-me";

/// `Debug` is hand-rolled to redact `client_secret` and `session_signing_key`.
/// Both are secrets and CLAUDE.md forbids them from appearing in logs/errors.
#[derive(Clone)]
pub struct AuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    /// OIDC `aud` value our ID tokens must carry. Most IdPs default this to
    /// `client_id`, but it can differ (e.g. resource-server-style audiences).
    pub audience: String,
    pub groups_claim: String,
    pub session_ttl: Duration,
    /// HMAC key for the gateway-issued session JWT. Distinct from IdP keys —
    /// we re-sign so we can revoke via the state DB denylist.
    pub session_signing_key: Vec<u8>,
    /// Skip the live IdP. Tests boot an in-process mock at `issuer` instead.
    pub mock_mode: bool,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_url", &self.redirect_url)
            .field("audience", &self.audience)
            .field("groups_claim", &self.groups_claim)
            .field("session_ttl", &self.session_ttl)
            .field("session_signing_key", &"<redacted>")
            .field("mock_mode", &self.mock_mode)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthConfigError {
    #[error("invalid SESSION_TTL_HOURS `{value}`: {source}")]
    SessionTtl {
        value: String,
        source: std::num::ParseIntError,
    },
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_url: "http://localhost:8443/auth/callback".to_string(),
            audience: String::new(),
            groups_claim: DEFAULT_GROUPS_CLAIM.to_string(),
            session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_HOURS * 3600),
            session_signing_key: DEFAULT_DEV_SIGNING_KEY.as_bytes().to_vec(),
            mock_mode: false,
        }
    }
}

impl AuthConfig {
    /// Read auth config from environment. Defaults are dev-friendly; production
    /// boot should set every field explicitly (validated in #16's YAML pass).
    pub fn from_env() -> Result<Self, AuthConfigError> {
        let mut config = AuthConfig::default();

        if let Ok(value) = std::env::var("OIDC_ISSUER") {
            config.issuer = value;
        }
        if let Ok(value) = std::env::var("OIDC_CLIENT_ID") {
            config.client_id = value;
        }
        if let Ok(value) = std::env::var("OIDC_CLIENT_SECRET") {
            config.client_secret = value;
        }
        if let Ok(value) = std::env::var("OIDC_REDIRECT_URL") {
            config.redirect_url = value;
        }
        if let Ok(value) = std::env::var("OIDC_AUDIENCE") {
            config.audience = value;
        } else if !config.client_id.is_empty() {
            config.audience = config.client_id.clone();
        }
        if let Ok(value) = std::env::var("OIDC_GROUPS_CLAIM") {
            config.groups_claim = value;
        }
        if let Ok(value) = std::env::var("SESSION_TTL_HOURS") {
            let hours: u64 = value
                .parse()
                .map_err(|source| AuthConfigError::SessionTtl { value, source })?;
            config.session_ttl = Duration::from_secs(hours * 3600);
        }
        if let Ok(value) = std::env::var("SESSION_SIGNING_KEY") {
            config.session_signing_key = value.into_bytes();
        }
        if let Ok(value) = std::env::var("OIDC_MOCK_MODE") {
            config.mock_mode = matches!(value.as_str(), "1" | "true" | "TRUE");
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_groups_and_eight_hour_ttl() {
        let config = AuthConfig::default();
        assert_eq!(config.groups_claim, "groups");
        assert_eq!(config.session_ttl, Duration::from_secs(8 * 3600));
        assert!(!config.mock_mode);
    }
}
