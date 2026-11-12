//! Auth configuration: the OIDC client identity, claim mapping, and the
//! gateway-side session JWT signing key.
//!
//! Lives in env for now; folds into the YAML schema with issue #16. Tests
//! build `AuthConfig` directly against an in-process mock IdP (`tests/common/`).

use std::time::Duration;

use super::oauth::DEFAULT_REFRESH_TTL;
use super::oidc::is_loopback;

const DEFAULT_GROUPS_CLAIM: &str = "groups";
const DEFAULT_SESSION_TTL_HOURS: u64 = 8;
const DEFAULT_DEV_SIGNING_KEY: &str = "dev-only-session-signing-key-change-me";
/// Bounds on `SESSION_TTL_HOURS`: a session JWT is a bearer, so a week caps a
/// leaked one; refresh keeps a client signed in past that.
const SESSION_TTL_HOURS_MAX: u64 = 7 * 24;
/// Bounds on `REFRESH_TTL_DAYS`: the chain TTL is also the group-staleness
/// window (see [`DEFAULT_REFRESH_TTL`]). A year (+1 for leap years) because
/// deployments run year-long logins by owner decision, offset by prompt
/// revocation (logout, `/revoke`, admin revoke-sessions).
const REFRESH_TTL_DAYS_MAX: u64 = 366;
/// Shortest `SESSION_SIGNING_KEY` the gateway will boot with, in bytes.
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
    /// Absolute lifetime of a refresh-token *chain* (see [`DEFAULT_REFRESH_TTL`]
    /// for the group-staleness rationale). Rotation renews the opaque value but
    /// never this deadline. Overridable via `REFRESH_TTL_DAYS`.
    pub refresh_ttl: Duration,
    /// HMAC key for the gateway-issued session JWT. Distinct from IdP keys —
    /// we re-sign so we can revoke via the state DB denylist.
    pub session_signing_key: Vec<u8>,
    /// `ALLOW_INSECURE_SIGNING_KEY`: accept the committed dev key or a short
    /// key. Local dev only — refused unless the issuer is a loopback URL.
    pub allow_insecure_signing_key: bool,
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
            .field(
                "allow_insecure_signing_key",
                &self.allow_insecure_signing_key,
            )
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthConfigError {
    #[error("{var} is required")]
    Missing { var: &'static str },
    #[error("invalid {var} `{value}`: expected a whole number from 1 to {max}")]
    Ttl {
        var: &'static str,
        value: String,
        max: u64,
    },
    /// The committed dev signing key would be used to sign production session
    /// JWTs (A1). The key is public in this repo, so anyone could mint a
    /// valid-signature bearer. Message carries no key material.
    #[error(
        "SESSION_SIGNING_KEY is unset, empty, shorter than 32 bytes, or equals \
         the committed dev default; set a unique key of at least 32 bytes, or \
         set ALLOW_INSECURE_SIGNING_KEY=true for local dev against a loopback IdP"
    )]
    DefaultSigningKey,
    /// The insecure-key escape hatch is local-dev only; with a real IdP it
    /// would let anyone holding the public dev key mint bearers.
    #[error("ALLOW_INSECURE_SIGNING_KEY requires a loopback OIDC_ISSUER")]
    InsecureKeyWithRemoteIssuer,
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
            refresh_ttl: DEFAULT_REFRESH_TTL,
            session_signing_key: DEFAULT_DEV_SIGNING_KEY.as_bytes().to_vec(),
            allow_insecure_signing_key: false,
        }
    }
}

impl AuthConfig {
    /// Read auth config from environment and validate it: issuer and client id
    /// are required, TTLs bounded, the signing key strong unless explicitly
    /// waived for a loopback IdP.
    pub fn from_env() -> Result<Self, AuthConfigError> {
        let mut config = AuthConfig {
            issuer: required("OIDC_ISSUER")?,
            client_id: required("OIDC_CLIENT_ID")?,
            ..AuthConfig::default()
        };
        if let Ok(value) = std::env::var("OIDC_CLIENT_SECRET") {
            config.client_secret = value;
        }
        if let Ok(value) = std::env::var("OIDC_REDIRECT_URL") {
            config.redirect_url = value;
        }
        config.audience =
            std::env::var("OIDC_AUDIENCE").unwrap_or_else(|_| config.client_id.clone());
        if let Ok(value) = std::env::var("OIDC_GROUPS_CLAIM") {
            config.groups_claim = value;
        }
        if let Ok(value) = std::env::var("SESSION_TTL_HOURS") {
            config.session_ttl =
                parse_ttl("SESSION_TTL_HOURS", &value, 3600, SESSION_TTL_HOURS_MAX)?;
        }
        if let Ok(value) = std::env::var("REFRESH_TTL_DAYS") {
            config.refresh_ttl =
                parse_ttl("REFRESH_TTL_DAYS", &value, 24 * 3600, REFRESH_TTL_DAYS_MAX)?;
        }
        if let Ok(value) = std::env::var("SESSION_SIGNING_KEY") {
            config.session_signing_key = value.into_bytes();
        }
        if let Ok(value) = std::env::var("ALLOW_INSECURE_SIGNING_KEY") {
            config.allow_insecure_signing_key = matches!(value.as_str(), "1" | "true" | "TRUE");
        }

        check_signing_key(&config)?;
        if config.allow_insecure_signing_key {
            tracing::warn!(
                "ALLOW_INSECURE_SIGNING_KEY is set: session JWTs may be signed with a weak \
                 or public key; local development only"
            );
        }
        Ok(config)
    }
}

fn required(var: &'static str) -> Result<String, AuthConfigError> {
    std::env::var(var)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(AuthConfigError::Missing { var })
}

/// Parse a whole number of `unit_secs` units in `1..=max`.
fn parse_ttl(
    var: &'static str,
    value: &str,
    unit_secs: u64,
    max: u64,
) -> Result<Duration, AuthConfigError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=max).contains(n))
        .and_then(|n| n.checked_mul(unit_secs))
        .map(Duration::from_secs)
        .ok_or_else(|| AuthConfigError::Ttl {
            var,
            value: value.to_string(),
            max,
        })
}

/// Refuse a session signing key that is the committed dev default or too
/// short to be a credible HMAC secret (A1), unless the operator waived that
/// for a loopback IdP — the waiver with a real IdP is itself refused.
fn check_signing_key(config: &AuthConfig) -> Result<(), AuthConfigError> {
    if config.allow_insecure_signing_key {
        return match url::Url::parse(&config.issuer) {
            Ok(issuer) if is_loopback(&issuer) => Ok(()),
            _ => Err(AuthConfigError::InsecureKeyWithRemoteIssuer),
        };
    }
    if config.session_signing_key == DEFAULT_DEV_SIGNING_KEY.as_bytes()
        || config.session_signing_key.len() < MIN_SIGNING_KEY_BYTES
    {
        return Err(AuthConfigError::DefaultSigningKey);
    }
    Ok(())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
