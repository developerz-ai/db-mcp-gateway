//! Service tokens: static bearer credentials for headless (non-interactive)
//! clients — CI jobs, agent runners, anything that cannot drive a browser SSO
//! flow. Design and operator runbook: website/docs/initial-idea/14-service-tokens.md.
//!
//! A service token is declared in the YAML config (`service_accounts:`) with a
//! name, exactly one permissions group, and a `${ENV:…}` / `${FILE:…}` secret
//! reference. This module resolves those references once at boot into an
//! in-memory store; `bearer_auth` consults the store before falling through to
//! the session-JWT path. There is deliberately no in-band mint/rotate/revoke
//! API — issuance and revocation are GitOps edits (reviewed by PR) plus a
//! secret-store update and a rollout.
//!
//! Security review required (see CLAUDE.md). Token material never appears in
//! `Debug`/`Display` for anything in this module; the store compare is
//! constant-time.

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret as _, SecretString};

/// Strict boot-time shape check: `dbmcp_svc_` + exactly 64 lowercase
/// ASCII-hex characters. Anything else (short, overlong, non-hex,
/// mixed-case, missing prefix) is rejected with `WeakToken`.
fn is_well_formed_token(token: &str) -> bool {
    let Some(body) = token.strip_prefix(TOKEN_PREFIX) else {
        return false;
    };
    if body.len() != TOKEN_BODY_CHARS {
        return false;
    }
    body.bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

use super::pkce::ct_eq;
use super::session::{Identity, IdentityKind, SERVICE_SUBJECT_PREFIX, SessionId};
use crate::config::ServiceAccount;
use crate::config::secret::SecretError;

/// Required token prefix. Self-identifying tokens are scannable (leak
/// detection can key on the prefix) and make a mis-pasted credential —
/// a session JWT, a DB password — fail boot loudly instead of silently
/// authenticating as nothing. `bin/mint-service-token` emits this shape.
pub const TOKEN_PREFIX: &str = "dbmcp_svc_";

/// Exact body length: 64 lowercase-ASCII-hex characters (32 bytes of CSPRNG
/// entropy). Enforced at boot so a weak, mis-pasted, or out-of-shape token
/// cannot reach the compare loop. `bin/mint-service-token` emits this shape.
pub const TOKEN_BODY_CHARS: usize = 64;

/// One resolved service account: name, group, and the live token value.
/// `Debug` shows name + group (operator-useful, not secret) and redacts the
/// token the same way `Password` redacts DB credentials.
#[derive(Clone)]
struct ResolvedServiceToken {
    name: String,
    group: String,
    policy: ServicePolicy,
    token: SecretString,
}

/// Per-account request policy from `service_accounts:`, attached to every
/// request the account authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePolicy {
    /// Refuse calls that do not carry both `x-dbmcp-run-id` and
    /// `x-dbmcp-on-behalf-of` (`invalid_arguments`, audited).
    pub require_upstream: bool,
    /// In-flight cap for this account, replacing the per-identity default —
    /// a fleet of agents behind one token is not capped at one human's share.
    /// `None` keeps the default.
    pub max_concurrent_requests: Option<usize>,
}

impl std::fmt::Debug for ResolvedServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedServiceToken")
            .field("name", &self.name)
            .field("group", &self.group)
            .field("policy", &self.policy)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// What can go wrong turning `service_accounts:` config into a store. Every
/// variant names the account and the rule violated; none carries a byte of
/// token material (same discipline as `config::secret::SecretError`).
#[derive(Debug, thiserror::Error)]
pub enum ServiceTokenError {
    #[error("service account `{0}`: token reference does not resolve")]
    Resolve(String, #[source] SecretError),

    #[error(
        "service account `{0}`: token must be `{TOKEN_PREFIX}` followed by exactly \
         {TOKEN_BODY_CHARS} lowercase hexadecimal characters — generate one with \
         `bin/mint-service-token {0}`"
    )]
    WeakToken(String),

    /// Two accounts resolving to the same value would make audit attribution
    /// ambiguous — a call could be either identity. Rejected at boot.
    #[error("service accounts `{0}` and `{1}` resolve to the same token value")]
    DuplicateToken(String, String),
}

/// The boot-resolved set of service tokens. Linear scan on authenticate: the
/// configured count is expected to stay in the single digits, and a scan keeps
/// every comparison constant-time without a hash map keyed by secret material.
///
/// `Arc`-shared: `AppState` clones per request, and a `Vec<SecretString>`
/// clone would copy live token material across the heap on every call. The
/// values are immutable after boot, so one allocation serves every request.
#[derive(Debug, Default, Clone)]
pub struct ServiceTokenStore {
    tokens: std::sync::Arc<[ResolvedServiceToken]>,
}

impl ServiceTokenStore {
    /// Resolve + validate every configured account. Runs at boot (via `main`)
    /// after `ConfigFile::load`; any failure aborts startup — a gateway that
    /// can't honour its configured auth surface must not serve.
    pub fn from_config(accounts: &[ServiceAccount]) -> Result<Self, ServiceTokenError> {
        let mut tokens: Vec<ResolvedServiceToken> = Vec::with_capacity(accounts.len());
        for account in accounts {
            let token = account
                .token
                .resolve()
                .map_err(|source| ServiceTokenError::Resolve(account.name.clone(), source))?;
            let exposed = token.expose_secret();
            if !is_well_formed_token(exposed) {
                return Err(ServiceTokenError::WeakToken(account.name.clone()));
            }
            // Reject shared values now so `authenticate` never has to pick
            // between two identities for one presented token.
            for existing in &tokens {
                if ct_eq(
                    existing.token.expose_secret().as_bytes(),
                    exposed.as_bytes(),
                ) {
                    return Err(ServiceTokenError::DuplicateToken(
                        existing.name.clone(),
                        account.name.clone(),
                    ));
                }
            }
            tokens.push(ResolvedServiceToken {
                name: account.name.clone(),
                group: account.group.clone(),
                policy: ServicePolicy {
                    require_upstream: account.require_upstream,
                    max_concurrent_requests: account
                        .max_concurrent_requests
                        .map(|cap| usize::try_from(cap).unwrap_or(usize::MAX)),
                },
                token,
            });
        }
        Ok(Self {
            tokens: tokens.into(),
        })
    }

    /// Match a presented bearer against the store. `Some(identity)` on an
    /// exact, constant-time match; `None` defers to the session-JWT path —
    /// a non-match here is NOT an auth failure on its own.
    pub fn authenticate(&self, presented: &str) -> Option<Identity> {
        self.authenticate_caller(presented)
            .map(|(identity, _)| identity)
    }

    /// [`Self::authenticate`] plus the account's [`ServicePolicy`].
    pub fn authenticate_caller(&self, presented: &str) -> Option<(Identity, ServicePolicy)> {
        let now = Utc::now();
        self.tokens
            .iter()
            .find(|entry| ct_eq(entry.token.expose_secret().as_bytes(), presented.as_bytes()))
            .map(|entry| (entry.identity(now), entry.policy))
    }
}

impl ResolvedServiceToken {
    fn identity(&self, now: DateTime<Utc>) -> Identity {
        Identity {
            // No session row backs a service identity — nothing to revoke or
            // expire DB-side (revocation is a config edit + rollout). The id
            // is per-request decoration for the debug log line only; audit
            // attribution runs through `user_sub` below.
            session_id: SessionId::new(),
            user_sub: format!("{SERVICE_SUBJECT_PREFIX}{}", self.name),
            // Synthesized: `audit_calls.user_email` is NOT NULL and every
            // identity carries one. The `.invalid` TLD (RFC 2606) marks it
            // as non-routable on purpose.
            user_email: format!("{}@service-accounts.invalid", self.name),
            groups: vec![self.group.clone()],
            // Per-request "issue time": there is no login instant for a static
            // token, and the admin session-age gate never sees these (the
            // boot-time group check keeps service groups off `/admin/*`).
            issued_at: now,
            kind: IdentityKind::Service,
        }
    }
}

#[cfg(test)]
#[path = "service_token_tests.rs"]
mod tests;
