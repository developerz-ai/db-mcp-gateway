//! Load + validate the gateway's `servers:` and `permissions:` from YAML.
//!
//! For #3 this is a strict subset of the spec doc 08 schema. The remaining
//! sections (`gateway:`, `auth:`, `logging:`) come from env/AuthConfig today
//! and land in YAML with issue #16.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::schema::{Permission, Server};

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    #[error("failed to read config file `{path}`")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file `{path}`")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> Result<Self, ConfigFileError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_yaml_str(&raw).map_err(|err| match err {
            ConfigFileError::Parse { source, .. } => ConfigFileError::Parse {
                path: path.to_path_buf(),
                source,
            },
            other => other,
        })
    }

    pub fn from_yaml_str(raw: &str) -> Result<Self, ConfigFileError> {
        let parsed: ConfigFile =
            serde_yaml::from_str(raw).map_err(|source| ConfigFileError::Parse {
                path: PathBuf::from("<inline>"),
                source,
            })?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), ConfigFileError> {
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
}
