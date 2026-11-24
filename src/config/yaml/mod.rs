//! Load + validate the gateway's YAML config (spec 08). Every section, and
//! the top level itself, denies unknown keys: a misspelled section name fails
//! boot instead of being silently ignored. OIDC and listener settings are
//! env-driven (`AuthConfig`, `Config`), not YAML.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::schema::{
    ConstraintProfiles, LoggingBlock, Permission, PermissionSpec, Server, ServerSpec,
    ServiceAccount, ServiceAccountSpec, apply_constraint_profiles,
};
use super::secret::{SecretError, SiteSecretError};
use admin::AdminBlock;

pub use admin::{AdminConfig, AdminGroup};
pub use error::ConfigFileError;
pub use gateway::{Environment, GatewayBlock};

mod admin;
mod error;
mod gateway;
mod limits;
mod reload_diff;
mod roles;
mod secret_refs;
mod service_accounts;
mod targets;
mod validate;
mod validate_profiles;
mod write_tier;

#[derive(Debug, Clone)]
pub struct ConfigFile {
    /// `env: production` rejects inline literal secrets. Absent → development.
    pub gateway: GatewayBlock,
    pub servers: Vec<Server>,
    pub permissions: Vec<Permission>,
    /// Spec 12 §"Admin API". Belt-and-suspenders for YAML-only installs.
    pub admin: AdminConfig,
    /// Spec 12 §"Storage backends" (#59). Absent → use the state DB
    /// (Postgres) as the permissions store too — the default. Present
    /// with `driver: mysql` connects to a separate mysql pool via
    /// `PERMISSIONS_DB_DSN` env; `driver: none` runs YAML-only. The state
    /// DB itself (sessions, audit rows) stays Postgres regardless. Read it
    /// through [`ConfigFile::permissions_store_driver`].
    pub permissions_store: Option<PermissionsStoreBlock>,
    /// Headless service identities (spec 14). Absent → no static bearer
    /// token is accepted; the OIDC session path is the only way in.
    pub service_accounts: Vec<ServiceAccount>,
    /// Spec 07 §Storage. Absent → no stream sinks, the pre-#218 behavior.
    pub logging: LoggingBlock,
}

/// The YAML as written. Converted into [`ConfigFile`] once, at the parse edge,
/// so sections with cross-field rules (`admin:`) reach callers already typed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfigFile {
    #[serde(default)]
    gateway: GatewayBlock,
    #[serde(default)]
    servers: Vec<ServerSpec>,
    #[serde(default)]
    permissions: Vec<PermissionSpec>,
    /// Named constraint sets grants reference by `profile:`; folded into the
    /// grants here, so `ConfigFile` carries only resolved constraints.
    #[serde(default)]
    constraint_profiles: ConstraintProfiles,
    #[serde(default)]
    admin: Option<AdminBlock>,
    #[serde(default)]
    permissions_store: Option<PermissionsStoreBlock>,
    #[serde(default)]
    service_accounts: Vec<ServiceAccountSpec>,
    #[serde(default)]
    logging: LoggingBlock,
}

impl RawConfigFile {
    /// `servers:` and `permissions:` convert here rather than in serde: a
    /// parse error drops its message (it could quote the file), these keep it.
    fn into_config(self) -> Result<ConfigFile, ConfigFileError> {
        let servers = self
            .servers
            .into_iter()
            .map(Server::try_from)
            .collect::<Result<_, _>>()
            .map_err(ConfigFileError::Invalid)?;
        let mut permissions = self
            .permissions
            .into_iter()
            .map(Permission::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ConfigFileError::Invalid)?;
        apply_constraint_profiles(&self.constraint_profiles, &mut permissions)
            .map_err(ConfigFileError::Invalid)?;
        Ok(ConfigFile {
            gateway: self.gateway,
            servers,
            permissions,
            admin: AdminConfig::from_block(self.admin)?,
            permissions_store: self.permissions_store,
            service_accounts: self
                .service_accounts
                .into_iter()
                .map(ServiceAccountSpec::into_account)
                .collect::<Result<_, _>>()
                .map_err(ConfigFileError::Invalid)?,
            logging: self.logging,
        })
    }
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

/// Where DB grants come from. Spec 12 §"Storage backends" explicitly
/// excludes mongo (flexible schema is a liability for an authz store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionsStoreDriver {
    Pg,
    Mysql,
    /// YAML-only: grants come from `permissions:` alone and no store is ever
    /// read. YAML `driver: none`.
    #[serde(rename = "none")]
    YamlOnly,
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
    /// Every unresolved reference, from [`ConfigFile::resolve_all_secrets`].
    #[error("{} secret reference(s) did not resolve:\n{}", .0.len(), list_secret_errors(.0))]
    Secrets(Vec<SiteSecretError>),
}

fn list_secret_errors(errors: &[SiteSecretError]) -> String {
    errors
        .iter()
        .map(|err| format!("  - {err}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl ConfigFile {
    /// The permissions store this config selects; an absent block is the
    /// state DB (`Pg`), the default since #59.
    pub fn permissions_store_driver(&self) -> PermissionsStoreDriver {
        self.permissions_store
            .as_ref()
            .map_or(PermissionsStoreDriver::Pg, |store| store.driver)
    }

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
        let raw: RawConfigFile = serde_saphyr::from_str_with_options(raw, non_leaking_options())
            .map_err(|source| ConfigFileError::parse_from(PathBuf::from("<inline>"), source))?;
        let mut parsed = raw.into_config()?;
        // Group names and user subjects are compared to IdP claims verbatim;
        // stray YAML whitespace would make a block silently match nobody.
        for permission in &mut parsed.permissions {
            permission.subject.trim();
        }
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
                if let Some(write_password) = &db.write_password {
                    let _ = write_password.resolve()?;
                }
            }
        }
        for account in &self.service_accounts {
            // Same fail-fast contract as DB passwords: an unresolvable
            // service-token ref aborts boot here. The request path reads the
            // value back out of `ServiceTokenStore`, built at startup.
            for token in &account.tokens {
                let _ = token.resolve()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
