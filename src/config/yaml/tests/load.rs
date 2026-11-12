//! `load_yaml_str`: the fail-fast parse + secret-resolution boot path.

use crate::config::secret::SecretError;
use crate::config::yaml::{ConfigFile, ConfigFileError, ConfigLoadError};

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
