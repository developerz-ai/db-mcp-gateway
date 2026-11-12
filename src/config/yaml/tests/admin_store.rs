//! `admin:`, `permissions_store:`, `auth_database` and server-kind boot gates.

use crate::config::yaml::{ConfigFile, ConfigFileError, PermissionsStoreDriver};

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
