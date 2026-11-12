//! Servers, databases, roles and grant cross-references.

use super::SAMPLE;
use crate::config::ServerKind;
use crate::config::yaml::roles::reject_superuser_role;
use crate::config::yaml::{ConfigFile, ConfigFileError};

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
    let src = include_str!("../../../../config/example.yaml");
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
