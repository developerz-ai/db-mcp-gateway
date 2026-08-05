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

use super::pkce::ct_eq;
use super::session::{Identity, SessionId};
use crate::config::ServiceAccount;
use crate::config::secret::SecretError;

/// Required token prefix. Self-identifying tokens are scannable (leak
/// detection can key on the prefix) and make a mis-pasted credential —
/// a session JWT, a DB password — fail boot loudly instead of silently
/// authenticating as nothing. `bin/mint-service-token` emits this shape.
pub const TOKEN_PREFIX: &str = "dbmcp_svc_";

/// Shortest accepted token, in characters: the prefix plus 32 random
/// characters (128 bits of entropy at hex density — the mint verb emits 64).
/// Shorter values are rejected at boot so a weak token can never reach the
/// compare loop.
pub const MIN_TOKEN_CHARS: usize = TOKEN_PREFIX.len() + 32;

/// One resolved service account: name, group, and the live token value.
/// `Debug` shows name + group (operator-useful, not secret) and redacts the
/// token the same way `Password` redacts DB credentials.
#[derive(Clone)]
struct ResolvedServiceToken {
    name: String,
    group: String,
    token: SecretString,
}

impl std::fmt::Debug for ResolvedServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedServiceToken")
            .field("name", &self.name)
            .field("group", &self.group)
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
        "service account `{0}`: token must start with `{TOKEN_PREFIX}` and be at least \
         {MIN_TOKEN_CHARS} characters — generate one with `bin/mint-service-token {0}`"
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
            if !(exposed.starts_with(TOKEN_PREFIX) && exposed.len() >= MIN_TOKEN_CHARS) {
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
        let now = Utc::now();
        self.tokens
            .iter()
            .find(|entry| ct_eq(entry.token.expose_secret().as_bytes(), presented.as_bytes()))
            .map(|entry| entry.identity(now))
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
            user_sub: format!("service:{}", self.name),
            // Synthesized: `audit_calls.user_email` is NOT NULL and every
            // identity carries one. The `.invalid` TLD (RFC 2606) marks it
            // as non-routable on purpose.
            user_email: format!("{}@service-accounts.invalid", self.name),
            groups: vec![self.group.clone()],
            // Per-request "issue time": there is no login instant for a static
            // token, and the admin session-age gate never sees these (the
            // boot-time group check keeps service groups off `/admin/*`).
            issued_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthError;
    use crate::config::Password;

    fn account(name: &str, group: &str, token: &str) -> ServiceAccount {
        ServiceAccount {
            name: name.to_string(),
            group: group.to_string(),
            token: Password::Literal(SecretString::from(token)),
        }
    }

    fn good_token(suffix: &str) -> String {
        // Prefix + 32+ chars of body, differentiated by the suffix so each
        // test token is distinct.
        format!("{TOKEN_PREFIX}{suffix:0>32}")
    }

    #[test]
    fn authenticates_a_configured_token() {
        let store = ServiceTokenStore::from_config(&[
            account("ci-bot", "svc-ci", &good_token("a")),
            account("nightly", "svc-nightly", &good_token("b")),
        ])
        .expect("valid accounts build a store");

        let identity = store
            .authenticate(&good_token("a"))
            .expect("exact token match authenticates");
        assert_eq!(identity.user_sub, "service:ci-bot");
        assert_eq!(identity.user_email, "ci-bot@service-accounts.invalid");
        assert_eq!(identity.groups, vec!["svc-ci".to_string()]);
    }

    #[test]
    fn unknown_or_near_miss_tokens_do_not_match() {
        let store =
            ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &good_token("a"))])
                .expect("valid account builds a store");

        // `None` here means "fall through to the JWT path", not acceptance.
        assert!(store.authenticate(&good_token("b")).is_none());
        // One byte flipped at the tail.
        let mut near = good_token("a");
        near.replace_range(near.len() - 1.., "z");
        assert!(store.authenticate(&near).is_none());
        // Truncated / extended / empty.
        let short = &good_token("a")[..MIN_TOKEN_CHARS - 1];
        assert!(store.authenticate(short).is_none());
        assert!(
            store
                .authenticate(&format!("{}x", good_token("a")))
                .is_none()
        );
        assert!(store.authenticate("").is_none());
    }

    #[test]
    fn empty_store_matches_nothing() {
        let store = ServiceTokenStore::default();
        assert!(store.authenticate(&good_token("a")).is_none());
    }

    #[test]
    fn prefixless_token_is_rejected_at_boot() {
        let err = ServiceTokenStore::from_config(&[account(
            "ci-bot",
            "svc-ci",
            "0123456789abcdef0123456789abcdef",
        )])
        .expect_err("missing prefix must fail the build");
        assert!(matches!(&err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
        // The operator-facing message names the mint verb — and no token bytes.
        let rendered = format!("{err}");
        assert!(rendered.contains("bin/mint-service-token"), "{rendered}");
        assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
    }

    #[test]
    fn short_token_is_rejected_at_boot() {
        let weak = format!("{TOKEN_PREFIX}tooshort");
        let err = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &weak)])
            .expect_err("short token must fail the build");
        assert!(matches!(err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
    }

    #[test]
    fn duplicate_token_value_is_rejected_at_boot() {
        let err = ServiceTokenStore::from_config(&[
            account("ci-bot", "svc-ci", &good_token("a")),
            account("ci-bot-2", "svc-ci", &good_token("a")),
        ])
        .expect_err("a shared token value breaks audit attribution");
        assert!(
            matches!(&err, ServiceTokenError::DuplicateToken(first, second)
                if first == "ci-bot" && second == "ci-bot-2")
        );
        // Names only, never the value.
        let rendered = format!("{err}");
        assert!(!rendered.contains(&good_token("a")), "{rendered}");
    }

    #[test]
    fn unresolved_reference_is_a_boot_error_without_material() {
        let missing = format!("DB_MCP_SVC_TEST_{}", uuid::Uuid::new_v4().simple());
        let accounts = [ServiceAccount {
            name: "ci-bot".to_string(),
            group: "svc-ci".to_string(),
            token: Password::EnvVar(missing.clone()),
        }];
        let err = ServiceTokenStore::from_config(&accounts)
            .expect_err("unset env ref must fail the build");
        match err {
            ServiceTokenError::Resolve(name, SecretError::EnvNotSet(var)) => {
                assert_eq!(name, "ci-bot");
                assert_eq!(var, missing);
            }
            other => panic!("expected Resolve(EnvNotSet), got {other:?}"),
        }
    }

    /// Defends the no-creds-in-Debug rule: the store and its entries must
    /// never render token material.
    #[test]
    fn debug_never_prints_token_material() {
        let store =
            ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &good_token("c"))])
                .expect("valid account builds a store");
        let rendered = format!("{store:?}");
        assert!(rendered.contains("ci-bot"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains(&good_token("c")), "{rendered}");
        assert!(!rendered.contains(TOKEN_PREFIX), "{rendered}");
    }

    /// The middleware logs `identity.session_id` on every request; pin the
    /// redaction contract of the identity itself (email is PII-shaped even
    /// when synthesized).
    #[test]
    fn service_identity_debug_redacts_email() {
        let store =
            ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &good_token("d"))])
                .expect("valid account builds a store");
        let identity = store.authenticate(&good_token("d")).expect("match");
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("service:ci-bot"), "{rendered}");
        assert!(!rendered.contains("service-accounts.invalid"), "{rendered}");
    }

    /// Belt-and-suspenders for `AuthError`: if a future refactor maps a
    /// service-token failure onto an auth error, that error must still carry
    /// no token material. Pins the enum's existing discipline as it applies
    /// to this feature.
    #[test]
    fn auth_errors_carry_no_token_material() {
        let token = good_token("e");
        for err in [AuthError::MissingBearer, AuthError::InvalidSession] {
            assert!(!format!("{err}").contains(&token));
        }
    }
}
