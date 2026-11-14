//! `kind: redis` servers: the stock `default` ACL user, the numeric
//! database index, and the fields Redis has no use for.

use crate::config::ServerKind;
use crate::config::yaml::{ConfigFile, ConfigFileError};

fn redis_yaml(database: &str) -> String {
    format!(
        "servers:\n  - name: cache\n    kind: redis\n    host: h\n    \
         databases:\n      - {database}\n"
    )
}

fn invalid_message(database: &str) -> String {
    match ConfigFile::from_yaml_str(&redis_yaml(database)) {
        Err(ConfigFileError::Invalid(message)) => message,
        other => panic!("expected Invalid for `{database}`, got {other:?}"),
    }
}

/// `default` holds `+@all ~* &*` on a stock server — the Redis superuser.
#[test]
fn rejects_the_default_acl_user_in_any_case() {
    for role in ["default", "Default"] {
        let yaml = redis_yaml(&format!("{{ name: \"0\", role: {role}, password: x }}"));
        match ConfigFile::from_yaml_str(&yaml) {
            Err(ConfigFileError::StockSuperuserRole {
                role: got, kind, ..
            }) => {
                assert_eq!(got, role);
                assert_eq!(kind, ServerKind::Redis);
            }
            other => panic!("`{role}` must be refused at boot, got {other:?}"),
        }
    }
}

/// The database name is the logical index, in one canonical spelling.
#[test]
fn rejects_a_database_name_that_is_not_a_canonical_index() {
    for name in ["app", "-1", "+1", "01", "1.0", " 1", "4294967296"] {
        let message = invalid_message(&format!(
            "{{ name: \"{name}\", role: gateway_ro, password: x }}"
        ));
        assert!(
            message.contains("logical database index"),
            "{name}: {message}"
        );
    }
}

#[test]
fn rejects_auth_database_on_redis() {
    let message =
        invalid_message("{ name: \"0\", role: gateway_ro, password: x, auth_database: admin }");
    assert!(message.contains("auth_database"), "{message}");
}

#[test]
fn rejects_a_write_role_on_redis() {
    let message = invalid_message(
        "{ name: \"0\", role: gateway_ro, password: x, write_role: rw, write_password: y }",
    );
    assert!(message.contains("write_role"), "{message}");
}

#[test]
fn accepts_a_least_privilege_redis_target_on_the_default_port() {
    let config = ConfigFile::from_yaml_str(&redis_yaml(
        "{ name: \"3\", role: gateway_ro, password: x }",
    ))
    .expect("a numeric index with a non-default ACL user boots");
    let server = &config.servers[0];
    assert_eq!(server.kind, ServerKind::Redis);
    assert_eq!(server.port, 6379);
    assert_eq!(server.databases[0].name, "3");
}
