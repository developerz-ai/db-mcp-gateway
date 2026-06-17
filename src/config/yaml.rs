//! Load + validate the gateway's `servers:` and `permissions:` from YAML.
//!
//! For #3 this is a strict subset of the spec doc 08 schema. The remaining
//! sections (`gateway:`, `auth:`, `logging:`) come from env/AuthConfig today
//! and land in YAML with issue #16.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::schema::{Permission, Server};
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
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    #[error("failed to read config file `{path}`")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// `Display` is the operator-facing line and we want it self-contained:
    /// path, line:column (when serde_yaml supplies it), and the underlying
    /// reason — including serde's `unknown field, expected one of …`
    /// suggestion list. Chained via `source` so structured loggers still
    /// walk the underlying `serde_yaml::Error`.
    #[error("{path}{location}: {message}")]
    Parse {
        path: PathBuf,
        /// `:line:column` when serde_yaml knows it, empty otherwise.
        location: String,
        /// Pre-rendered `source` text — keeps `Display` operator-friendly
        /// without forcing every caller to walk the error chain.
        message: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
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

        let mut server_names: HashSet<&str> = HashSet::new();
        for server in &self.servers {
            if !server_names.insert(&server.name) {
                return Err(ConfigFileError::Invalid(format!(
                    "duplicate server name `{}`",
                    server.name
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
            }
        }

        let mut group_names: HashSet<&str> = HashSet::new();
        for permission in &self.permissions {
            if !group_names.insert(&permission.group) {
                return Err(ConfigFileError::Invalid(format!(
                    "duplicate permission group `{}`",
                    permission.group
                )));
            }
            for grant in &permission.grants {
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
        // Names the misspelled key, lists the right ones, and points at the line.
        assert!(
            rendered.contains("statemnt_timeout_ms"),
            "missing misspelled key: {rendered}"
        );
        assert!(
            rendered.contains("statement_timeout_ms"),
            "missing suggestion: {rendered}"
        );
        // serde_yaml reports the line of the offending key. Exact column varies
        // by serde_yaml version; assert just on a `:line:column` shape.
        assert!(
            rendered.contains(":14:") || rendered.contains(":13:"),
            "expected `:14:` or `:13:` line marker in: {rendered}"
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
        assert!(rendered.contains("descriptoin"), "missing key: {rendered}");
        assert!(
            rendered.contains("description"),
            "missing suggestion: {rendered}"
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
        assert!(rendered.contains("query_reed"), "missing got: {rendered}");
        assert!(
            rendered.contains("query_read"),
            "missing expected: {rendered}"
        );
    }
}
