//! Load + validate the gateway's `servers:` and `permissions:` from YAML.
//!
//! For #3 this is a strict subset of the spec doc 08 schema. The remaining
//! sections (`gateway:`, `auth:`, `logging:`) come from env/AuthConfig today
//! and land in YAML with issue #16.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::schema::{Permission, Server, ServerKind};
use super::secret::SecretError;

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

#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    #[error("failed to read config file `{path}`")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// `Display` deliberately omits the raw serde_yaml message: that text can
    /// echo an offending scalar (e.g. a password mis-pasted into a typed field)
    /// verbatim into the boot log. We surface only `path` + `:line:column` so
    /// operators can find the offending line without the value being printed.
    /// The full serde reason stays reachable via the `source` chain for callers
    /// (tests, structured loggers) that opt into walking it.
    #[error("{path}{location}: invalid configuration")]
    Parse {
        path: PathBuf,
        /// `:line:column` when serde_yaml knows it, empty otherwise.
        location: String,
        /// Pre-rendered `source` text. Kept for callers that walk the error
        /// chain; never rendered by `Display` (see the variant doc comment).
        message: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
    /// CLAUDE.md: "Never run as DB superuser. Per-DB read-only roles, full
    /// stop." Split out from `Invalid` so callers (structured loggers, tests,
    /// future admin surfaces) classify this outcome by variant rather than
    /// substring-matching a message that's free to evolve.
    #[error(
        "database `{db_name}` in server `{server_name}` connects as `{role}`, \
         the stock superuser for `{kind:?}`. The gateway must never hold a \
         superuser credential — create a per-database read-only role and use \
         that instead (see \
         https://developerz-ai.github.io/db-mcp-gateway/docs/initial-idea/credentials)"
    )]
    StockSuperuserRole {
        role: String,
        kind: ServerKind,
        db_name: String,
        server_name: String,
    },
}

impl ConfigFileError {
    /// Build a `Parse` error with location information extracted up-front.
    /// Operators read `Display` first; making them dig through `source()`
    /// for line numbers is the polish #16 is fixing.
    fn parse_from(path: PathBuf, source: serde_yaml::Error) -> Self {
        let location = source
            .location()
            .map(|loc| format!(":{}:{}", loc.line(), loc.column()))
            .unwrap_or_default();
        let message = source.to_string();
        ConfigFileError::Parse {
            path,
            location,
            message,
            source,
        }
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
            ConfigFileError::Parse {
                location,
                message,
                source,
                ..
            } => ConfigFileError::Parse {
                path: path.to_path_buf(),
                location,
                message,
                source,
            },
            other => other,
        })
    }

    /// Parse + structural validation only. See `from_file` for the contract;
    /// use `load_yaml_str` for the fail-fast variant.
    pub fn from_yaml_str(raw: &str) -> Result<Self, ConfigFileError> {
        let parsed: ConfigFile = serde_yaml::from_str(raw)
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
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigFileError> {
        if let Some(admin) = &self.admin
            && admin.enabled
            && admin.group.trim().is_empty()
        {
            return Err(ConfigFileError::Invalid(
                "admin.group must be non-empty when admin.enabled is true".to_string(),
            ));
        }

        // #59 scope: mysql is wired for the resolver hot path only. The
        // admin handlers use raw pg `RETURNING` + `JSONB` operations
        // that haven't been ported. Boot fails fast rather than running
        // with a half-wired admin surface.
        if let (Some(store), Some(admin)) = (&self.permissions_store, &self.admin)
            && store.driver == PermissionsStoreDriver::Mysql
            && admin.enabled
        {
            return Err(ConfigFileError::Invalid(
                "permissions_store.driver = mysql is not supported with admin.enabled = true. \
                 #59 wires mysql for the resolver hot path only; full admin parity is tracked \
                 in a future issue. Either set admin.enabled = false or use driver = pg."
                    .to_string(),
            ));
        }

        let mut server_names: HashSet<&str> = HashSet::new();
        for server in &self.servers {
            if !server_names.insert(&server.name) {
                return Err(ConfigFileError::Invalid(format!(
                    "duplicate server name `{}`",
                    server.name
                )));
            }
            // The lazy `AdapterRegistry` (src/exec/mod.rs) dispatches only
            // postgres + mongo today; a `mysql`/`mssql` target parses, boots
            // clean, then fails every query with `UnsupportedAdapter`. Reject
            // at boot instead — spec 08 "errors at this stage refuse to start".
            // `ServerKind::has_adapter` is the shared source of truth with the
            // registry's dispatch match.
            if !server.kind.has_adapter() {
                return Err(ConfigFileError::Invalid(format!(
                    "server `{}` has kind `{:?}`, which has no query adapter yet \
                     (supported kinds: postgres, mongo)",
                    server.name, server.kind
                )));
            }
            let mut db_names: HashSet<&str> = HashSet::new();
            for db in &server.databases {
                if !db_names.insert(&db.name) {
                    return Err(ConfigFileError::Invalid(format!(
                        "duplicate database `{}` in server `{}`",
                        db.name, server.name
                    )));
                }
                validate_role(&db.role).map_err(ConfigFileError::Invalid)?;
                reject_superuser_role(&db.role, server.kind, &db.name, &server.name)?;
                // `Some("")` would silently override the `None → name` fallback
                // and force mongo to authenticate against an empty `authSource`,
                // surfacing as a cryptic runtime auth failure instead of a boot
                // error. Mirrors the `admin.group` non-empty rule above — every
                // optional-string field that *means something when present*
                // gets the same trim check.
                if let Some(auth_db) = &db.auth_database
                    && auth_db.trim().is_empty()
                {
                    return Err(ConfigFileError::Invalid(format!(
                        "database `{}` in server `{}` has empty `auth_database`; \
                         omit the field to fall back to `name`, or set a non-blank value",
                        db.name, server.name
                    )));
                }
            }
        }

        let mut group_names: HashSet<&str> = HashSet::new();
        for permission in &self.permissions {
            // An empty/whitespace group name would silently grant this block to
            // any identity carrying a blank group claim. Same meaning-when-present
            // rule as `admin.group` and `auth_database` above — reject at boot.
            if permission.group.trim().is_empty() {
                return Err(ConfigFileError::Invalid(
                    "permission group name must be non-empty".to_string(),
                ));
            }
            if !group_names.insert(&permission.group) {
                return Err(ConfigFileError::Invalid(format!(
                    "duplicate permission group `{}`",
                    permission.group
                )));
            }
            for grant in &permission.grants {
                // Empty/whitespace `server`/`database` would otherwise surface as
                // a cryptic "unknown server ``" from the existence checks below;
                // reject up front for a clear boot error. (`*` is the wildcard.)
                if grant.server.trim().is_empty() {
                    return Err(ConfigFileError::Invalid(format!(
                        "permission group `{}` has a grant with an empty `server`",
                        permission.group
                    )));
                }
                if grant.database.trim().is_empty() {
                    return Err(ConfigFileError::Invalid(format!(
                        "permission group `{}` has a grant with an empty `database`",
                        permission.group
                    )));
                }
                if grant.server != "*" && !server_names.contains(grant.server.as_str()) {
                    return Err(ConfigFileError::Invalid(format!(
                        "permission group `{}` grants on unknown server `{}`",
                        permission.group, grant.server
                    )));
                }
                if grant.database != "*"
                    && !grant_database_exists(&self.servers, &grant.server, &grant.database)
                {
                    return Err(ConfigFileError::Invalid(format!(
                        "permission group `{}` grants on unknown database `{}` of server `{}`",
                        permission.group, grant.database, grant.server
                    )));
                }
            }
        }
        Ok(())
    }
}

fn grant_database_exists(servers: &[Server], server_name: &str, db_name: &str) -> bool {
    // Wildcard server still requires the database name to exist somewhere —
    // otherwise typos like `database: app-typo` are accepted silently and
    // surface only as cryptic runtime auth misses.
    if server_name == "*" {
        return servers
            .iter()
            .any(|s| s.databases.iter().any(|d| d.name == db_name));
    }
    servers
        .iter()
        .find(|s| s.name == server_name)
        .map(|s| s.databases.iter().any(|d| d.name == db_name))
        .unwrap_or(false)
}

/// The stock superuser/root account each backend ships with. Connecting as one
/// defeats the whole per-database least-privilege model — the gateway's
/// read-only guarantee then rests entirely on the SQL guard, with no
/// defense-in-depth underneath it, and a guard escape becomes a full compromise
/// of the target. CLAUDE.md states it flatly: "Never run as DB superuser.
/// Per-DB read-only roles, full stop." Rejected at boot rather than trusted to
/// review (#136).
///
/// This matches on the stock *name*, not on actual privilege — a superuser
/// renamed to `app` still passes, and this check can't see the grants behind
/// it. It closes the overwhelmingly common case (someone points the gateway at
/// the account their DB shipped with); the real guarantee remains the
/// least-privilege role the operator provisions target-side.
fn stock_superuser_roles(kind: ServerKind) -> &'static [&'static str] {
    match kind {
        ServerKind::Postgres => &["postgres"],
        ServerKind::Mysql => &["root"],
        ServerKind::Mssql => &["sa"],
        ServerKind::Mongo => &["root", "admin"],
    }
}

fn reject_superuser_role(
    role: &str,
    kind: ServerKind,
    db_name: &str,
    server_name: &str,
) -> Result<(), ConfigFileError> {
    // Role names are case-insensitive in practice across these backends, and an
    // operator writing `Postgres` means the same account as `postgres`.
    let lowered = role.to_ascii_lowercase();
    if stock_superuser_roles(kind).contains(&lowered.as_str()) {
        return Err(ConfigFileError::StockSuperuserRole {
            role: role.to_string(),
            kind,
            db_name: db_name.to_string(),
            server_name: server_name.to_string(),
        });
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), String> {
    // Per spec 08: `^[a-zA-Z_][a-zA-Z0-9_]*$`. Catch role typos at boot rather
    // than as cryptic connection failures later.
    let mut chars = role.chars();
    let first = chars.next().ok_or_else(|| "empty role name".to_string())?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!(
            "role `{role}` must start with a letter or underscore"
        ));
    }
    for ch in chars {
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            return Err(format!(
                "role `{role}` contains invalid char `{ch}` (allowed: alphanumerics + underscore)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: Customer-facing prod
    host: prod.db.internal
    port: 5432
    tls: required
    databases:
      - name: app
        role: mcp_gateway_prod_app_ro
        password: vault:secret/prod/app_ro
        description: Main app DB
      - name: billing
        role: mcp_gateway_prod_billing_ro
        password: vault:secret/prod/billing_ro
  - name: staging
    kind: postgres
    host: staging.db.internal
    databases:
      - name: app
        role: mcp_gateway_staging_app_ro
        password: hunter2

permissions:
  - group: backend-engineers
    grants:
      - server: staging
        database: "*"
        action: query_read
      - server: prod
        database: "*"
        action: schema_read
"#;

    #[test]
    fn parses_a_realistic_config() {
        let config = ConfigFile::from_yaml_str(SAMPLE).unwrap();
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.permissions.len(), 1);
        let prod = &config.servers[0];
        assert_eq!(prod.name, "prod");
        assert_eq!(prod.databases.len(), 2);
    }

    #[test]
    fn rejects_duplicate_server_names() {
        let yaml = r#"
servers:
  - { name: dup, kind: postgres, host: a }
  - { name: dup, kind: postgres, host: b }
"#;
        assert!(matches!(
            ConfigFile::from_yaml_str(yaml),
            Err(ConfigFileError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_grant_on_unknown_server() {
        let yaml = r#"
servers:
  - { name: prod, kind: postgres, host: a }
permissions:
  - group: g
    grants:
      - { server: ghost, database: "*", action: query_read }
"#;
        assert!(matches!(
            ConfigFile::from_yaml_str(yaml),
            Err(ConfigFileError::Invalid(_))
        ));
    }

    /// Parsing the committed example file catches breaking schema drift
    /// before it ships. Sections we don't yet model (`gateway:`, `auth:`,
    /// `logging:`) are silently ignored — that's intentional until #16.
    #[test]
    fn parses_the_committed_example_file() {
        let src = include_str!("../../config/example.yaml");
        let config = ConfigFile::from_yaml_str(src).expect("example.yaml stays parseable");
        assert!(config.servers.iter().any(|s| s.name == "prod"));
        assert!(config.servers.iter().any(|s| s.name == "staging"));
        assert!(
            config
                .permissions
                .iter()
                .any(|p| p.group == "backend-engineers")
        );
    }

    #[test]
    fn rejects_duplicate_permission_group() {
        let yaml = r#"
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
permissions:
  - group: dup
    grants:
      - { server: prod, database: app, action: query_read }
  - group: dup
    grants:
      - { server: prod, database: app, action: schema_read }
"#;
        let err = ConfigFile::from_yaml_str(yaml).unwrap_err();
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid, got {err:?}");
        };
        assert!(msg.contains("dup"), "{msg}");
    }

    /// AZ1: an empty (or whitespace-only) group name would grant this block to
    /// any identity carrying a blank group claim. Reject at boot.
    #[test]
    fn rejects_empty_permission_group_name() {
        let yaml = r#"
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
permissions:
  - group: "   "
    grants:
      - { server: prod, database: app, action: query_read }
"#;
        let err = ConfigFile::from_yaml_str(yaml).expect_err("blank group must reject");
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid, got {err:?}");
        };
        assert!(msg.contains("non-empty"), "{msg}");
    }

    #[test]
    fn rejects_wildcard_server_grant_on_unknown_database() {
        let yaml = r#"
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
permissions:
  - group: g
    grants:
      - { server: "*", database: ghost, action: query_read }
"#;
        assert!(matches!(
            ConfigFile::from_yaml_str(yaml),
            Err(ConfigFileError::Invalid(_))
        ));
    }

    #[test]
    fn accepts_wildcard_server_grant_on_known_database() {
        let yaml = r#"
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
  - name: staging
    kind: postgres
    host: b
    databases:
      - { name: app, role: ro, password: y }
permissions:
  - group: g
    grants:
      - { server: "*", database: app, action: query_read }
"#;
        ConfigFile::from_yaml_str(yaml).expect("wildcard server + existing db is valid");
    }

    /// `load_yaml_str` is the canonical boot path: parse failure AND
    /// unresolved-secret failure both bubble out the same `?`, so `main`
    /// (and future `SIGHUP`) can't accidentally start with half-loaded state.
    #[test]
    fn load_yaml_str_aborts_on_unresolved_secret() {
        let yaml = r#"
servers:
  - name: s
    kind: postgres
    host: h
    databases:
      - { name: d, role: ro, password: vault:secret/x }
"#;
        // Vault backend isn't implemented → resolve fails → load fails.
        let err = ConfigFile::load_yaml_str(yaml).expect_err("vault ref must abort load");
        assert!(
            matches!(
                err,
                ConfigLoadError::Secret(SecretError::BackendNotImplemented(_))
            ),
            "expected ConfigLoadError::Secret(BackendNotImplemented), got {err:?}"
        );
    }

    /// Parse errors from `load_yaml_str` come through the same composite
    /// error — callers see one type at the boundary, not two.
    #[test]
    fn load_yaml_str_surfaces_parse_errors() {
        let yaml = r#"
servers:
  - { name: dup, kind: postgres, host: a }
  - { name: dup, kind: postgres, host: b }
"#;
        let err = ConfigFile::load_yaml_str(yaml).expect_err("duplicate names rejected");
        assert!(
            matches!(err, ConfigLoadError::File(ConfigFileError::Invalid(_))),
            "expected ConfigLoadError::File(Invalid), got {err:?}"
        );
    }

    /// Literals resolve trivially, so `load_yaml_str` returns the same
    /// `ConfigFile` shape as `from_yaml_str` for the happy path.
    #[test]
    fn load_yaml_str_succeeds_with_literal_passwords() {
        let yaml = r#"
servers:
  - name: s
    kind: postgres
    host: h
    databases:
      - { name: d, role: ro, password: hunter2 }
"#;
        let cfg = ConfigFile::load_yaml_str(yaml).expect("literal passwords resolve");
        assert_eq!(cfg.servers.len(), 1);
    }

    #[test]
    fn rejects_invalid_role_chars() {
        let yaml = r#"
servers:
  - name: s
    kind: postgres
    host: h
    databases:
      - { name: d, role: "has-dash", password: x }
"#;
        assert!(matches!(
            ConfigFile::from_yaml_str(yaml),
            Err(ConfigFileError::Invalid(_))
        ));
    }

    /// CLAUDE.md: "Never run as DB superuser. Per-DB read-only roles, full
    /// stop." Booting against the stock superuser used to be accepted (#136).
    /// The dedicated `StockSuperuserRole` variant lets callers classify this
    /// outcome without matching on message text (which is free to evolve).
    #[test]
    fn rejects_the_stock_superuser_role_per_backend() {
        // Only wired kinds are reachable here — `has_adapter` rejects the rest
        // first. `stock_superuser_roles` covers those directly, below.
        for (kind_str, expected_kind, role) in [
            ("postgres", ServerKind::Postgres, "postgres"),
            ("mongo", ServerKind::Mongo, "root"),
            ("mongo", ServerKind::Mongo, "admin"),
        ] {
            let yaml = format!(
                "servers:\n  - name: s\n    kind: {kind_str}\n    host: h\n    \
                 databases:\n      - {{ name: d, role: {role}, password: x }}\n"
            );
            let err = ConfigFile::from_yaml_str(&yaml)
                .expect_err("`{role}` on {kind_str} must be rejected at boot");
            match err {
                ConfigFileError::StockSuperuserRole {
                    role: got_role,
                    kind: got_kind,
                    db_name,
                    server_name,
                } => {
                    assert_eq!(got_role, role);
                    assert_eq!(got_kind, expected_kind);
                    assert_eq!(db_name, "d");
                    assert_eq!(server_name, "s");
                }
                other => panic!("expected StockSuperuserRole for {kind_str}/{role}, got {other:?}"),
            }
        }
    }

    /// Kinds without an adapter never reach the role check through config
    /// (`has_adapter` rejects them first), so pin their mapping directly —
    /// it must already be right on the day their adapter lands.
    #[test]
    fn every_backend_declares_its_stock_superuser() {
        assert!(matches!(
            reject_superuser_role("root", ServerKind::Mysql, "d", "s"),
            Err(ConfigFileError::StockSuperuserRole { .. })
        ));
        assert!(matches!(
            reject_superuser_role("sa", ServerKind::Mssql, "d", "s"),
            Err(ConfigFileError::StockSuperuserRole { .. })
        ));
        assert!(reject_superuser_role("app_ro", ServerKind::Mysql, "d", "s").is_ok());
    }

    /// Case is not a hiding place: these backends treat role names
    /// case-insensitively, so `Postgres` is the same account as `postgres`.
    /// The typed variant preserves the operator's original casing for the
    /// error message, so we assert on it too.
    #[test]
    fn superuser_rejection_is_case_insensitive() {
        let yaml = "servers:\n  - name: s\n    kind: postgres\n    host: h\n    \
                    databases:\n      - { name: d, role: PostgreS, password: x }\n";
        match ConfigFile::from_yaml_str(yaml) {
            Err(ConfigFileError::StockSuperuserRole { role, kind, .. }) => {
                assert_eq!(role, "PostgreS");
                assert_eq!(kind, ServerKind::Postgres);
            }
            other => panic!("expected StockSuperuserRole, got {other:?}"),
        }
    }

    /// The rule is per-backend: `root` is MySQL's superuser, not Postgres', and
    /// a Postgres role legitimately named `root` must still boot.
    #[test]
    fn superuser_names_do_not_leak_across_backends() {
        let yaml = "servers:\n  - name: s\n    kind: postgres\n    host: h\n    \
                    databases:\n      - { name: d, role: root, password: x }\n";
        assert!(
            ConfigFile::from_yaml_str(yaml).is_ok(),
            "`root` is not the Postgres superuser"
        );
    }

    /// The headline example from #16: a typo in a `Constraints` field used to
    /// be silently ignored (no timeout applied). Now it surfaces with the
    /// misspelled key, the expected alternatives, and a line number.
    #[test]
    fn typo_in_constraint_field_is_rejected_with_line_and_suggestion() {
        let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
permissions:
  - group: g
    grants:
      - server: prod
        database: app
        action: query_read
        constraints:
          statemnt_timeout_ms: 5000
";
        let err = ConfigFile::from_yaml_str(yaml).expect_err("typo must be rejected");
        let rendered = format!("{err}");
        // Display points at the line but must NOT echo the raw serde text
        // (which can carry an offending scalar). The misspelled key and the
        // suggestion list live in the `source` chain only.
        assert!(
            !rendered.contains("statemnt_timeout_ms"),
            "Display must not echo raw serde text: {rendered}"
        );
        // serde_yaml reports the line of the offending key. Exact column varies
        // by serde_yaml version; assert just on a `:line:column` shape.
        assert!(
            rendered.contains(":14:") || rendered.contains(":13:"),
            "expected `:14:` or `:13:` line marker in: {rendered}"
        );
        // The full reason — misspelled key + suggestions — stays reachable for
        // callers that walk the chain.
        let ConfigFileError::Parse { source, .. } = err else {
            panic!("expected Parse, got {err:?}");
        };
        let detail = source.to_string();
        assert!(
            detail.contains("statemnt_timeout_ms"),
            "missing misspelled key in source: {detail}"
        );
        assert!(
            detail.contains("statement_timeout_ms"),
            "missing suggestion in source: {detail}"
        );
    }

    /// A typo in a key on the next-most-likely error surface — a `Database`
    /// field — fails the same way. Defends the per-struct `deny_unknown_fields`
    /// coverage across the inner schema, not just `Constraints`.
    #[test]
    fn typo_in_database_field_is_rejected() {
        let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - name: app
        role: ro
        password: x
        descriptoin: typo here
";
        let err = ConfigFile::from_yaml_str(yaml).expect_err("typo must be rejected");
        let rendered = format!("{err}");
        // Same contract: Display stays scalar-free, suggestions live in source.
        assert!(
            !rendered.contains("descriptoin"),
            "Display must not echo raw serde text: {rendered}"
        );
        let ConfigFileError::Parse { source, .. } = err else {
            panic!("expected Parse, got {err:?}");
        };
        let detail = source.to_string();
        assert!(detail.contains("descriptoin"), "missing key: {detail}");
        assert!(
            detail.contains("description"),
            "missing suggestion: {detail}"
        );
    }

    /// Spec 12 §"Admin API": when `admin.enabled` is true, `admin.group`
    /// must be non-empty — otherwise every authenticated caller would be an
    /// admin. Boot-time rejection (not a silent default) is the contract.
    #[test]
    fn rejects_admin_enabled_with_blank_group() {
        let yaml = r#"
admin:
  enabled: true
  group: "   "
"#;
        let err = ConfigFile::from_yaml_str(yaml).expect_err("blank admin group must reject");
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid, got {err:?}");
        };
        assert!(msg.contains("admin.group"), "{msg}");
        assert!(msg.contains("non-empty"), "{msg}");
    }

    /// Mirror of the rejection test: `enabled: false` is the YAML-only
    /// install default and must parse cleanly regardless of `group` shape
    /// (the group string is ignored when the feature is off).
    #[test]
    fn accepts_admin_disabled_regardless_of_group() {
        let yaml = r#"
admin:
  enabled: false
  group: ""
"#;
        ConfigFile::from_yaml_str(yaml).expect("disabled admin parses even with blank group");

        let yaml_with_group = r#"
admin:
  enabled: false
  group: some-group
"#;
        ConfigFile::from_yaml_str(yaml_with_group)
            .expect("disabled admin parses with any group string");
    }

    /// The omitted-block path: no `admin:` at all. Absent ≡ disabled and
    /// the `/admin/*` surface stays 404 at the router layer.
    #[test]
    fn accepts_omitted_admin_block() {
        let yaml = "servers: []\npermissions: []\n";
        let cfg = ConfigFile::from_yaml_str(yaml).expect("omitted admin block is valid");
        assert!(cfg.admin.is_none());
        assert!(cfg.permissions_store.is_none());
    }

    /// #59 boot-gate: mysql permissions store + admin.enabled is rejected
    /// with a message pointing at the scope decision. Resolver-only mysql
    /// support is intentional; admin handlers use raw pg `RETURNING` and
    /// haven't been ported.
    #[test]
    fn rejects_mysql_store_with_admin_enabled() {
        let yaml = r#"
permissions_store:
  driver: mysql
admin:
  enabled: true
  group: admins
"#;
        let err = ConfigFile::from_yaml_str(yaml).expect_err("mysql + admin combo must reject");
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid, got {err:?}");
        };
        assert!(msg.contains("mysql"), "{msg}");
        assert!(msg.contains("admin.enabled"), "{msg}");
        assert!(msg.contains("#59"), "{msg}");
    }

    /// Mysql store + admin disabled is the supported config: resolver
    /// reads grants from mysql; YAML or pre-seeded tables manage them.
    #[test]
    fn accepts_mysql_store_with_admin_disabled() {
        let yaml = r#"
permissions_store:
  driver: mysql
"#;
        let cfg = ConfigFile::from_yaml_str(yaml).expect("mysql + no admin parses");
        assert_eq!(
            cfg.permissions_store.as_ref().map(|s| s.driver),
            Some(PermissionsStoreDriver::Mysql)
        );
    }

    /// Pg store + admin enabled is the default-functional config and
    /// must keep working.
    #[test]
    fn accepts_pg_store_with_admin_enabled() {
        let yaml = r#"
permissions_store:
  driver: pg
admin:
  enabled: true
  group: admins
"#;
        ConfigFile::from_yaml_str(yaml).expect("pg + admin parses");
    }

    /// `auth_database: ""` (or whitespace-only) would silently slip past
    /// deserialization and then fail at query time against mongo's
    /// authSource. Spec 08 says fields with meaning-when-present validate
    /// at boot — same rule as `admin.group`.
    #[test]
    fn rejects_empty_auth_database() {
        let yaml = r#"
servers:
  - name: s
    kind: mongo
    host: h
    databases:
      - { name: d, role: ro, password: x, auth_database: "   " }
"#;
        let err = ConfigFile::from_yaml_str(yaml).expect_err("blank auth_database must reject");
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid, got {err:?}");
        };
        assert!(msg.contains("auth_database"), "{msg}");
        assert!(msg.contains("non-blank") || msg.contains("omit"), "{msg}");
    }

    /// Mirror: `None` (field omitted) is the spec-blessed fallback path
    /// and must continue to parse cleanly.
    #[test]
    fn accepts_omitted_auth_database() {
        let yaml = r#"
servers:
  - name: s
    kind: mongo
    host: h
    databases:
      - { name: d, role: ro, password: x }
"#;
        let cfg = ConfigFile::from_yaml_str(yaml).expect("omitted auth_database is valid");
        assert!(cfg.servers[0].databases[0].auth_database.is_none());
    }

    /// A `mysql`/`mssql` server kind parses (the enum has the variants) but has
    /// no query adapter wired (`exec::AdapterRegistry` dispatches pg + mongo
    /// only). Reject at boot instead of failing every query at runtime with
    /// `UnsupportedAdapter`. Spec 08 §"Resolution order": validation errors
    /// refuse to start.
    #[test]
    fn rejects_undispatchable_server_kind() {
        for kind in ["mysql", "mssql"] {
            let yaml = format!(
                "\
servers:
  - name: legacy
    kind: {kind}
    host: h
"
            );
            let err = match ConfigFile::from_yaml_str(&yaml) {
                Err(err) => err,
                Ok(_) => panic!("kind `{kind}` must be rejected at boot"),
            };
            let ConfigFileError::Invalid(msg) = err else {
                panic!("expected Invalid for kind `{kind}`, got {err:?}");
            };
            assert!(msg.contains("legacy"), "{msg}");
            assert!(msg.contains("no query adapter"), "{msg}");
        }
    }

    /// Mirror: `mongo` IS a wired query target (#57), so it must keep passing
    /// validation — guards against the boot-gate over-rejecting.
    #[test]
    fn accepts_mongo_server_kind() {
        let yaml = r#"
servers:
  - name: docs
    kind: mongo
    host: h
    databases:
      - { name: app, role: ro, password: x }
"#;
        let cfg = ConfigFile::from_yaml_str(yaml).expect("mongo target is dispatchable");
        assert_eq!(cfg.servers.len(), 1);
    }

    /// A misspelled enum variant (action name) yields the same kind of
    /// expected-vs-got message serde gives for unknown variants — surfaces
    /// before the runtime can reach a confused authz miss.
    #[test]
    fn misspelled_action_is_rejected_with_variant_list() {
        let yaml = "\
servers:
  - { name: prod, kind: postgres, host: a, databases: [{ name: app, role: ro, password: x }] }
permissions:
  - group: g
    grants:
      - { server: prod, database: app, action: query_reed }
";
        let err = ConfigFile::from_yaml_str(yaml).expect_err("typo must be rejected");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("query_reed"),
            "Display must not echo raw serde text: {rendered}"
        );
        let ConfigFileError::Parse { source, .. } = err else {
            panic!("expected Parse, got {err:?}");
        };
        let detail = source.to_string();
        assert!(detail.contains("query_reed"), "missing got: {detail}");
        assert!(detail.contains("query_read"), "missing expected: {detail}");
    }

    /// C4: the rendered `Display` of a parse error must never carry the raw
    /// serde_yaml text — an offending scalar (potentially a secret) could ride
    /// along. The reason stays reachable only via the `source` chain.
    #[test]
    fn parse_error_display_omits_raw_serde_text() {
        // `port` wants u16; the string value is the kind of scalar serde would
        // otherwise echo verbatim into its message.
        let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    port: \"sup3r-s3cret-looking-scalar\"
";
        let err = ConfigFile::from_yaml_str(yaml).expect_err("type mismatch must be rejected");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("sup3r-s3cret-looking-scalar"),
            "Display leaked the offending scalar: {rendered}"
        );
        assert!(
            rendered.contains("invalid configuration"),
            "Display should be the generic operator line: {rendered}"
        );
        // The scalar is still available for chain-walking callers.
        let ConfigFileError::Parse { source, .. } = err else {
            panic!("expected Parse, got {err:?}");
        };
        assert!(
            source.to_string().contains("sup3r-s3cret-looking-scalar"),
            "source should retain the full serde reason"
        );
    }
}
