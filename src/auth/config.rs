//! Auth configuration: the OIDC client identity, claim mapping, and the
//! gateway-side session JWT signing key.
//!
//! Lives in env for now; folds into the YAML schema with issue #16. Mock mode
//! exists so CI doesn't need a real IdP — see `auth::oidc::OidcClient` and
//! the in-process mock in `tests/`.

use std::time::Duration;

const DEFAULT_GROUPS_CLAIM: &str = "groups";
const DEFAULT_SESSION_TTL_HOURS: u64 = 8;
/// Default absolute refresh-chain lifetime, in days, when `REFRESH_TTL_DAYS` is
/// unset. Conservative on purpose — see [`crate::transport::DEFAULT_REFRESH_TTL`]
/// for the group-staleness rationale. Operators raise it (up to a 90-day "stay
/// signed in" window) via `REFRESH_TTL_DAYS`.
const DEFAULT_REFRESH_TTL_DAYS: u64 = 1;
const DEFAULT_DEV_SIGNING_KEY: &str = "dev-only-session-signing-key-change-me";
/// Shortest `SESSION_SIGNING_KEY` a non-mock gateway will boot with, in bytes.
/// Matches the HS256 output length (RFC 7518 §3.2 floor). Also catches the
/// empty key: `SESSION_SIGNING_KEY=${SIGNING_KEY}` with the outer variable
/// unset expands to `""` in compose/Helm, which would otherwise HMAC every
/// session JWT with a zero-length key.
const MIN_SIGNING_KEY_BYTES: usize = 32;

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
    /// Absolute lifetime of a refresh-token *chain* (see
    /// [`crate::transport::DEFAULT_REFRESH_TTL`]). Rotation renews the opaque
    /// value but never this deadline. Overridable via `REFRESH_TTL_DAYS`.
    pub refresh_ttl: Duration,
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
            .field("refresh_ttl", &self.refresh_ttl)
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
    #[error("invalid REFRESH_TTL_DAYS `{value}`: {source}")]
    RefreshTtl {
        value: String,
        source: std::num::ParseIntError,
    },
    /// The committed dev signing key would be used to sign production session
    /// JWTs (A1). The key is public in this repo, so anyone could mint a
    /// valid-signature bearer. Message carries no key material.
    #[error(
        "SESSION_SIGNING_KEY is unset, empty, shorter than 32 bytes, or equals \
         the committed dev default; set a unique key of at least 32 bytes, or \
         enable OIDC_MOCK_MODE for local dev"
    )]
    DefaultSigningKey,
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
            refresh_ttl: Duration::from_secs(DEFAULT_REFRESH_TTL_DAYS * 24 * 3600),
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
        if let Ok(value) = std::env::var("REFRESH_TTL_DAYS") {
            let days: u64 = value
                .parse()
                .map_err(|source| AuthConfigError::RefreshTtl { value, source })?;
            config.refresh_ttl = Duration::from_secs(days * 24 * 3600);
        }
        if let Ok(value) = std::env::var("SESSION_SIGNING_KEY") {
            config.session_signing_key = value.into_bytes();
        }
        if let Ok(value) = std::env::var("OIDC_MOCK_MODE") {
            config.mock_mode = matches!(value.as_str(), "1" | "true" | "TRUE");
        }

        reject_default_signing_key(&config)?;
        Ok(config)
    }
}

/// Refuse to boot a non-mock gateway whose session signing key is the committed
/// dev default or too short to be a credible HMAC secret (A1). Mock mode is
/// exempt on both counts so CI / local dev needs no real key, and so short
/// fixture keys keep working there.
fn reject_default_signing_key(config: &AuthConfig) -> Result<(), AuthConfigError> {
    if config.mock_mode {
        return Ok(());
    }
    if config.session_signing_key == DEFAULT_DEV_SIGNING_KEY.as_bytes()
        || config.session_signing_key.len() < MIN_SIGNING_KEY_BYTES
    {
        return Err(AuthConfigError::DefaultSigningKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_groups_and_eight_hour_ttl() {
        let config = AuthConfig::default();
        assert_eq!(config.groups_claim, "groups");
        assert_eq!(config.session_ttl, Duration::from_secs(8 * 3600));
        assert_eq!(config.refresh_ttl, Duration::from_secs(24 * 3600));
        assert!(!config.mock_mode);
    }

    #[test]
    fn default_signing_key_rejected_in_non_mock() {
        let config = AuthConfig::default();
        assert!(matches!(
            reject_default_signing_key(&config),
            Err(AuthConfigError::DefaultSigningKey)
        ));
    }

    #[test]
    fn default_signing_key_allowed_in_mock() {
        let config = AuthConfig {
            mock_mode: true,
            ..AuthConfig::default()
        };
        assert!(reject_default_signing_key(&config).is_ok());
    }

    #[test]
    fn custom_signing_key_allowed() {
        // 32 bytes: the shortest key a non-mock gateway accepts.
        let config = AuthConfig {
            session_signing_key: b"a-unique-production-signing-key!".to_vec(),
            ..AuthConfig::default()
        };
        assert_eq!(config.session_signing_key.len(), MIN_SIGNING_KEY_BYTES);
        assert!(reject_default_signing_key(&config).is_ok());
    }

    /// `SESSION_SIGNING_KEY=` (e.g. `${SIGNING_KEY}` unset in compose/Helm)
    /// must not boot: an empty HMAC key signs every session JWT.
    #[test]
    fn empty_signing_key_rejected_in_non_mock() {
        let config = AuthConfig {
            session_signing_key: Vec::new(),
            ..AuthConfig::default()
        };
        assert!(matches!(
            reject_default_signing_key(&config),
            Err(AuthConfigError::DefaultSigningKey)
        ));
    }

    #[test]
    fn short_signing_key_rejected_in_non_mock() {
        let config = AuthConfig {
            session_signing_key: vec![b'k'; MIN_SIGNING_KEY_BYTES - 1],
            ..AuthConfig::default()
        };
        assert!(matches!(
            reject_default_signing_key(&config),
            Err(AuthConfigError::DefaultSigningKey)
        ));
    }

    /// Mock mode is the documented escape hatch for CI / local dev; short and
    /// empty keys stay legal there.
    #[test]
    fn short_and_empty_signing_keys_allowed_in_mock() {
        for key in [Vec::new(), b"short".to_vec()] {
            let config = AuthConfig {
                session_signing_key: key,
                mock_mode: true,
                ..AuthConfig::default()
            };
            assert!(reject_default_signing_key(&config).is_ok());
        }
    }

    /// The rejection message must never carry key material — it lands in logs.
    #[test]
    fn rejection_message_carries_no_key_material() {
        let message = AuthConfigError::DefaultSigningKey.to_string();
        assert!(!message.contains(DEFAULT_DEV_SIGNING_KEY), "{message}");
    }
}
