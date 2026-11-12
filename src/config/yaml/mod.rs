//! Load + validate the gateway's `servers:` and `permissions:` from YAML.
//!
//! For #3 this is a strict subset of the spec doc 08 schema. The remaining
//! sections (`gateway:`, `auth:`, `logging:`) come from env/AuthConfig today
//! and land in YAML with issue #16.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::schema::{LoggingBlock, Permission, Server, ServiceAccount};
use super::secret::SecretError;

pub use error::ConfigFileError;

mod error;
mod roles;
mod validate;

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// Spec 12 §"Admin API". Absent or `enabled: false` → entire `/admin/*`
    /// route returns 404. Belt-and-suspenders for YAML-only installs.
    #[serde(default)]
    pub admin: Option<AdminBlock>,
    /// Spec 12 §"Storage backends" (#59). Absent → use the state DB
    /// (Postgres) as the permissions store too — the default. Present
    /// with `driver: mysql` connects to a separate mysql pool via
    /// `PERMISSIONS_DB_DSN` env. The state DB itself (sessions, audit
    /// rows) stays Postgres regardless.
    #[serde(default)]
    pub permissions_store: Option<PermissionsStoreBlock>,
    /// Headless service identities (spec 14). Absent → no static bearer
    /// token is accepted; the OIDC session path is the only way in.
    #[serde(default)]
    pub service_accounts: Vec<ServiceAccount>,
    /// Spec 07 §Storage. Absent → no stream sinks, the pre-#218 behavior.
    #[serde(default)]
    pub logging: LoggingBlock,
}

/// Admin API gating. Mirrors spec 12 §"Admin API" YAML schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminBlock {
    #[serde(default)]
    pub enabled: bool,
    /// SSO group claim that authorizes `/admin/v1/*` calls. Required when
    /// `enabled = true`; an empty value is a boot error (every authenticated
    /// user would otherwise be an admin).
    pub group: String,
    /// Maximum age (in seconds) of a session before admin access is denied.
    /// When set, the admin middleware rejects sessions older than this limit
    /// regardless of `session_ttl_hours` — the caller must re-authenticate.
    ///
    /// **Why this matters:** group memberships are snapshotted at login. A user
    /// removed from the admin group in the IdP continues to pass the group check
    /// until their session expires (up to `session_ttl_hours`, default 8 h). Setting
    /// `session_max_age_secs` caps this window: e.g. `3600` (1 h) means a removed
    /// admin can act for at most one hour before the gateway forces re-login.
    ///
    /// Absent / `null` means "no age cap — rely on `session_ttl_hours` alone".
    #[serde(default)]
    pub session_max_age_secs: Option<u64>,
}

/// Permissions storage backend selection. The DSN is **not** in YAML — it
/// reads from `PERMISSIONS_DB_DSN` at startup, matching how `STATE_DB_URL`
/// works. Keeping connection strings out of YAML keeps secrets out of the
/// committed config and out of the boot-trace logs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsStoreBlock {
    pub driver: PermissionsStoreDriver,
}

/// The two supported permissions-store backends. Spec 12 §"Storage
/// backends" explicitly excludes mongo (flexible schema is a liability
/// for an authz store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionsStoreDriver {
    Pg,
    Mysql,
}

/// Parser options for every config parse in this module.
///
/// `serde-saphyr` defaults `with_snippet` to `true`, which wraps a failure in a
/// rustc-style window of the surrounding source. For a config file that is
/// mostly credentials, that turns any parse error into a credential disclosure:
/// a type error on one line drags its *neighbours* into the error value, and
/// from there into whatever walks the `source` chain. Disabling it keeps the
/// secret out of the error in the first place, which is stronger than redacting
/// it afterwards — there is nothing to forget to redact.
///
/// `location()` is unaffected, so operators still get `:line:column`.
///
/// `pub(super)` so sibling modules that parse config types reach for the same
/// options rather than the leaky default — see the note on `from_yaml_str`.
pub(super) fn non_leaking_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        with_snippet: false,
    }
}

/// Composite error returned by the canonical `ConfigFile::load*` path. Combines
/// parse/validate failures with secret-resolution failures so callers (i.e.
/// `main`) get a single `?` boundary and can't accidentally start with a
/// half-loaded config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error(transparent)]
    File(#[from] ConfigFileError),
    #[error(transparent)]
    Secret(#[from] SecretError),
}

impl ConfigFile {
    /// Canonical "load and fully validate" entry point — parses, validates,
    /// and resolves every secret reference. The boot path (`main`) and any
    /// future `SIGHUP` reload MUST use this so it's impossible to start with
    /// unresolved `${ENV:…}` / `${FILE:…}` refs lingering.
    ///
    /// Prefer this over `from_file` + `resolve_secrets`: the two-step path
    /// is parse-only and exists for tests and inspection tooling.
    pub fn load(path: &Path) -> Result<Self, ConfigLoadError> {
        let parsed = Self::from_file(path)?;
        parsed.resolve_secrets()?;
        Ok(parsed)
    }

    /// String-input twin of `load`. Same fail-fast contract; useful for
    /// in-memory configs (tests with literal passwords, `SIGHUP` reload
    /// once the watcher hands us the new YAML).
    pub fn load_yaml_str(raw: &str) -> Result<Self, ConfigLoadError> {
        let parsed = Self::from_yaml_str(raw)?;
        parsed.resolve_secrets()?;
        Ok(parsed)
    }

    /// Parse + structural validation only. **Does not resolve secrets** —
    /// the returned `ConfigFile` will silently carry unresolved `${ENV:…}` /
    /// `${FILE:…}` references. Use `load` for the boot path; this helper is
    /// for tests and config-inspection tooling that intentionally want to
    /// look at the parsed structure without touching the host environment.
    pub fn from_file(path: &Path) -> Result<Self, ConfigFileError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_yaml_str(&raw).map_err(|err| match err {
            // Re-stamp the placeholder path from `from_yaml_str` with the real one.
            ConfigFileError::Parse {
                location, expected, ..
            } => ConfigFileError::Parse {
                path: path.to_path_buf(),
                location,
                expected,
            },
            other => other,
        })
    }

    /// Parse + structural validation only. See `from_file` for the contract;
    /// use `load_yaml_str` for the fail-fast variant.
    ///
    /// The single place config YAML is parsed. Any new parse site must go
    /// through [`non_leaking_options`] too — `serde_saphyr::from_str` defaults
    /// to attaching source snippets, which on this file means credentials.
    pub fn from_yaml_str(raw: &str) -> Result<Self, ConfigFileError> {
        let parsed: ConfigFile = serde_saphyr::from_str_with_options(raw, non_leaking_options())
            .map_err(|source| ConfigFileError::parse_from(PathBuf::from("<inline>"), source))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Resolve every secret reference declared under `servers:`, fail fast
    /// on the first unresolved one. Per spec 05/08: the gateway must refuse
    /// to start rather than fail noisily on the user's first query. Returns
    /// the typed `SecretError` directly so callers (tests, the `SIGHUP`
    /// reload path) see exactly which env var or file went wrong.
    ///
    /// `load` / `load_yaml_str` call this for you; reach for `resolve_secrets`
    /// directly only when re-resolving an already-parsed config (e.g. a
    /// hot-reload watcher that wants to check rotated `${FILE:…}` mounts
    /// without re-parsing the YAML).
    ///
    /// Idempotent and side-effect-free against the config — the resolved
    /// plaintext is dropped immediately. Pool open re-resolves so file
    /// rotation still works without a restart.
    pub fn resolve_secrets(&self) -> Result<(), SecretError> {
        for server in &self.servers {
            for db in &server.databases {
                // Resolved value is dropped right here — never stored,
                // never logged.
                let _ = db.password.resolve()?;
            }
        }
        for account in &self.service_accounts {
            // Same fail-fast contract as DB passwords: an unresolvable
            // service-token ref aborts boot here. The request path reads the
            // value back out of `ServiceTokenStore`, built at startup.
            let _ = account.token.resolve()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
