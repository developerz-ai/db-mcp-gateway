//! `write_role` / `write_password` and the `query_write` boot rule.

use crate::config::yaml::{ConfigFile, ConfigFileError};

fn yaml(db_extra: &str, grant_db: &str, action: &str) -> String {
    format!(
        r#"
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - {{ name: app, role: app_ro, password: x{db_extra} }}
      - {{ name: billing, role: billing_ro, password: x }}
permissions:
  - group: devops
    grants:
      - {{ server: prod, database: "{grant_db}", action: {action} }}
"#
    )
}

const WRITE: &str = ", write_role: app_rw, write_password: y";

fn invalid(raw: &str) -> String {
    match ConfigFile::from_yaml_str(raw).expect_err("must reject") {
        ConfigFileError::Invalid(msg) => msg,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn query_write_on_a_database_with_write_role_boots() {
    let config = ConfigFile::from_yaml_str(&yaml(WRITE, "app", "query_write")).expect("boots");
    let db = &config.servers[0].databases[0];
    let (role, _) = db.write_credentials().expect("write tier configured");
    assert_eq!(role, "app_rw");
    assert_eq!(db.role, "app_ro");
}

#[test]
fn query_write_without_write_role_fails_boot() {
    let msg = invalid(&yaml("", "app", "query_write"));
    assert!(msg.contains("no `write_role`"), "{msg}");
    assert!(msg.contains("`app`"), "{msg}");
}

/// A wildcard expands to the configured databases; one read-only database
/// among them is enough to refuse the grant.
#[test]
fn wildcard_query_write_needs_write_role_on_every_match() {
    let msg = invalid(&yaml(WRITE, "*", "query_write"));
    assert!(msg.contains("`billing`"), "{msg}");
}

#[test]
fn read_grants_need_no_write_role() {
    ConfigFile::from_yaml_str(&yaml("", "*", "query_read")).expect("boots");
}

#[test]
fn write_role_and_password_come_as_a_pair() {
    let msg = invalid(&yaml(", write_role: app_rw", "app", "query_read"));
    assert!(msg.contains("without `write_password`"), "{msg}");
    let msg = invalid(&yaml(", write_password: y", "app", "query_read"));
    assert!(msg.contains("without `write_role`"), "{msg}");
}

#[test]
fn write_role_must_differ_from_the_read_role() {
    let msg = invalid(&yaml(
        ", write_role: app_ro, write_password: y",
        "app",
        "query_read",
    ));
    assert!(msg.contains("same role"), "{msg}");
}

#[test]
fn write_role_is_shape_and_superuser_checked() {
    let msg = invalid(&yaml(
        ", write_role: \"bad-role\", write_password: y",
        "app",
        "query_read",
    ));
    assert!(msg.contains("bad-role"), "{msg}");
    let err = ConfigFile::from_yaml_str(&yaml(
        ", write_role: postgres, write_password: y",
        "app",
        "query_read",
    ))
    .expect_err("superuser write role must reject");
    assert!(
        matches!(err, ConfigFileError::StockSuperuserRole { .. }),
        "{err:?}"
    );
}

#[test]
fn write_role_is_postgres_only() {
    let raw = r#"
servers:
  - name: docs
    kind: mongo
    host: a
    port: 27017
    databases:
      - { name: app, role: reader, password: x, write_role: writer, write_password: y }
"#;
    let msg = invalid(raw);
    assert!(msg.contains("only postgres"), "{msg}");
}

#[test]
fn production_rejects_a_literal_write_password() {
    let raw = r#"
gateway: { env: production }
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: app_ro, password: "${ENV:RO}", write_role: app_rw, write_password: s3cr3t-lit }
"#;
    let msg = invalid(raw);
    assert!(msg.contains("write_password"), "{msg}");
    assert!(!msg.contains("s3cr3t-lit"), "{msg}");
}
