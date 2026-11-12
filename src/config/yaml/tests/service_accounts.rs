//! `service_accounts:` (spec 14).

use crate::config::secret::SecretError;
use crate::config::yaml::{ConfigFile, ConfigFileError, ConfigLoadError};

// ------------------------------------------------------------------
// service_accounts (spec 14)
// ------------------------------------------------------------------

const SERVICE_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
permissions:
  - group: svc-ci
    grants:
      - { server: prod, database: app, action: query_read }
service_accounts:
  - name: ci-bot
    group: svc-ci
    token: dbmcp_svc_0123456789abcdef0123456789abcdef
"#;

#[test]
fn parses_service_accounts() {
    let config = ConfigFile::from_yaml_str(SERVICE_YAML).expect("service accounts parse");
    assert_eq!(config.service_accounts.len(), 1);
    let account = &config.service_accounts[0];
    assert_eq!(account.name, "ci-bot");
    assert_eq!(account.group, "svc-ci");
    // The token is a `Password` (Deserialize-only secret ref) — match the
    // variant rather than ever printing it.
    assert!(matches!(account.token, crate::config::Password::Literal(_)));
}

#[test]
fn rejects_duplicate_service_account_names() {
    let yaml = SERVICE_YAML.replace(
            "token: dbmcp_svc_0123456789abcdef0123456789abcdef",
            "token: dbmcp_svc_0123456789abcdef0123456789abcdef\n  - name: ci-bot\n    group: svc-ci\n    token: dbmcp_svc_fedcba9876543210fedcba9876543210",
        );
    let err = ConfigFile::from_yaml_str(&yaml).expect_err("duplicate name must reject");
    let ConfigFileError::Invalid(msg) = err else {
        panic!("expected Invalid, got {err:?}");
    };
    assert!(msg.contains("duplicate service account"), "{msg}");
    assert!(msg.contains("ci-bot"), "{msg}");
}

/// The name becomes the audit identity (`service:<name>`), so charset and
/// length are bounded at boot, not trusted to review.
#[test]
fn rejects_bad_service_account_names() {
    for bad in ["Ci-bot", "-ci-bot", "ci bot", "ci_bot", &"x".repeat(64)] {
        let yaml = SERVICE_YAML.replace("name: ci-bot", &format!("name: \"{bad}\""));
        let err = ConfigFile::from_yaml_str(&yaml).expect_err("name `{bad}` must reject");
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid for `{bad}`, got {err:?}");
        };
        assert!(msg.contains("service account name"), "{msg}");
    }
}

#[test]
fn rejects_service_account_with_blank_group() {
    let yaml = SERVICE_YAML.replace("group: svc-ci\n    token", "group: \"  \"\n    token");
    let err = ConfigFile::from_yaml_str(&yaml).expect_err("blank group must reject");
    let ConfigFileError::Invalid(msg) = err else {
        panic!("expected Invalid, got {err:?}");
    };
    assert!(msg.contains("must name a permissions group"), "{msg}");
}

/// A token bound to a group with no `permissions:` block authenticates
/// cleanly and then reaches nothing — almost always a typo. Fail at boot,
/// same rule as grants on unknown servers.
#[test]
fn rejects_service_account_group_without_permissions_block() {
    let yaml = SERVICE_YAML.replace("group: svc-ci\n    token", "group: svc-typo\n    token");
    let err = ConfigFile::from_yaml_str(&yaml).expect_err("undeclared group must reject");
    let ConfigFileError::Invalid(msg) = err else {
        panic!("expected Invalid, got {err:?}");
    };
    assert!(msg.contains("svc-typo"), "{msg}");
    assert!(msg.contains("permissions:"), "{msg}");
}

/// The admin middleware gates on group membership alone, so the boot gate
/// is what keeps a service token off `/admin/*` (spec 14; issue #185 AC:
/// admin reuse is not widened).
#[test]
fn rejects_service_account_mapped_to_the_admin_group() {
    let yaml = format!("{SERVICE_YAML}\nadmin:\n  enabled: true\n  group: svc-ci\n");
    let err = ConfigFile::from_yaml_str(&yaml).expect_err("admin-group mapping must reject");
    let ConfigFileError::Invalid(msg) = err else {
        panic!("expected Invalid, got {err:?}");
    };
    assert!(msg.contains("admin group"), "{msg}");
}

/// With the admin surface disabled the same group name is harmless — the
/// route never mounts — so the gate stays off, mirroring the
/// `admin.group` non-empty rule which also applies only when enabled.
#[test]
fn accepts_admin_group_name_when_admin_disabled() {
    let yaml = format!("{SERVICE_YAML}\nadmin:\n  enabled: false\n  group: svc-ci\n");
    ConfigFile::from_yaml_str(&yaml).expect("disabled admin makes the group check moot");
}

/// Service-token refs join the same fail-fast boot contract as DB
/// passwords: `load_yaml_str` must abort on an unresolvable ref.
#[test]
fn load_aborts_on_unresolved_service_token_ref() {
    let yaml = SERVICE_YAML.replace(
        "token: dbmcp_svc_0123456789abcdef0123456789abcdef",
        "token: ${ENV:DB_MCP_SVC_TEST_DEFINITELY_UNSET}",
    );
    let err = ConfigFile::load_yaml_str(&yaml).expect_err("unresolved ref must abort load");
    assert!(
        matches!(err, ConfigLoadError::Secret(SecretError::EnvNotSet(_))),
        "expected ConfigLoadError::Secret(EnvNotSet), got {err:?}"
    );
}
