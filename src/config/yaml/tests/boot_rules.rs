//! Plan 101 slice 10 step 5: unknown keys, zero/blank values and production
//! literals each fail boot — one row per rejected form, plus the forms that
//! must still pass.

use crate::config::yaml::{ConfigFile, ConfigFileError, Environment};

const SERVER: &str = r#"
servers:
  - name: s
    kind: postgres
    host: h
    databases:
      - { name: d, role: ro, password: "${ENV:DB_PW}" }
"#;

fn with_server(extra: &str) -> String {
    format!("{SERVER}{extra}")
}

fn rejected(yaml: &str) -> ConfigFileError {
    ConfigFile::from_yaml_str(yaml).expect_err("config must be rejected")
}

#[test]
fn unknown_top_level_and_section_keys_fail_boot() {
    for yaml in [
        with_server("permisions: []\n"),
        with_server("auth:\n  oidc: {}\n"),
        with_server("gateway:\n  bind: 0.0.0.0:8443\n"),
        with_server("gateway:\n  env: staging\n"),
    ] {
        assert!(
            matches!(rejected(&yaml), ConfigFileError::Parse { .. }),
            "accepted: {yaml}"
        );
    }
}

#[test]
fn zero_and_blank_values_fail_boot() {
    let cases = [
        (
            "servers:\n  - { name: ' ', kind: postgres, host: h }\n",
            "name",
        ),
        (
            "servers:\n  - { name: s, kind: postgres, host: ' ' }\n",
            "blank `host`",
        ),
        (
            "servers:\n  - { name: s, kind: postgres, host: h, port: 0 }\n",
            "port: 0",
        ),
        (
            "servers:\n  - name: s\n    kind: postgres\n    host: h\n    databases:\n      - { name: '', role: ro, password: x }\n",
            "blank `name`",
        ),
    ];
    for (yaml, needle) in cases {
        let err = rejected(yaml).to_string();
        assert!(err.contains(needle), "{yaml}: {err}");
    }
    for field in ["row_limit", "statement_timeout_ms"] {
        let yaml = with_server(&format!(
            "permissions:\n  - group: g\n    grants:\n      - {{ server: s, database: d, action: query_read, constraints: {{ {field}: 0 }} }}\n"
        ));
        let err = rejected(&yaml).to_string();
        assert!(err.contains(&format!("{field}: 0")), "{err}");
    }
}

#[test]
fn production_rejects_inline_literal_secrets() {
    let db_literal = "gateway: { env: production }\nservers:\n  - name: s\n    kind: postgres\n    host: h\n    databases:\n      - { name: d, role: ro, password: hunter2 }\n";
    let err = rejected(db_literal).to_string();
    assert!(err.contains("servers[s].databases[d].password"), "{err}");
    assert!(!err.contains("hunter2"), "literal echoed: {err}");

    let token_literal = with_server(
        "gateway: { env: production }\npermissions:\n  - { group: svc, grants: [] }\nservice_accounts:\n  - { name: bot, group: svc, token: dbmcp_svc_literal }\n",
    );
    let err = rejected(&token_literal).to_string();
    assert!(err.contains("service_accounts[bot].token"), "{err}");
    assert!(!err.contains("dbmcp_svc_literal"), "literal echoed: {err}");
}

#[test]
fn references_pass_in_production_and_literals_pass_in_development() {
    let prod = with_server("gateway: { env: production }\n");
    let config = ConfigFile::from_yaml_str(&prod).expect("refs are fine in production");
    assert_eq!(config.gateway.env, Environment::Production);

    let dev = "servers:\n  - name: s\n    kind: postgres\n    host: h\n    databases:\n      - { name: d, role: ro, password: hunter2 }\n";
    let config = ConfigFile::from_yaml_str(dev).expect("literals tolerated by default");
    assert_eq!(config.gateway.env, Environment::Development);
}

#[test]
fn pool_min_above_max_fails_boot_at_either_level() {
    let server_level = "servers:\n  - { name: s, kind: postgres, host: h, pool: { max_connections: 2, min_connections: 3 } }\n";
    assert!(rejected(server_level).to_string().contains("server `s`"));
    let db_level = "servers:\n  - name: s\n    kind: postgres\n    host: h\n    databases:\n      - { name: d, role: ro, password: x, pool: { max_connections: 1, min_connections: 2 } }\n";
    assert!(rejected(db_level).to_string().contains("database `d`"));
    let across_levels = "servers:\n  - name: s\n    kind: postgres\n    host: h\n    pool: { max_connections: 2 }\n    databases:\n      - { name: d, role: ro, password: x, pool: { min_connections: 3 } }\n";
    assert!(rejected(across_levels).to_string().contains("merged"));
    let zero_max =
        "servers:\n  - { name: s, kind: postgres, host: h, pool: { max_connections: 0 } }\n";
    assert!(matches!(rejected(zero_max), ConfigFileError::Parse { .. }));

    let ok = "servers:\n  - name: s\n    kind: postgres\n    host: h\n    pool: { max_connections: 4, min_connections: 0, idle_timeout_s: 300 }\n    databases:\n      - { name: d, role: ro, password: x, pool: { max_connections: 2 } }\n";
    let config = ConfigFile::from_yaml_str(ok).expect("valid pools parse");
    let server = &config.servers[0];
    assert_eq!(
        server.pool.and_then(|p| p.max_connections).map(|n| n.get()),
        Some(4)
    );
    assert_eq!(
        server.databases[0]
            .pool
            .and_then(|p| p.max_connections)
            .map(|n| n.get()),
        Some(2)
    );
}

#[test]
fn tls_ca_file_needs_verify_full_and_a_readable_file() {
    let without_verify = "servers:\n  - { name: s, kind: postgres, host: h, tls: required, tls_ca_file: /etc/hosts }\n";
    assert!(
        rejected(without_verify)
            .to_string()
            .contains("without `tls: verify_full`")
    );
    let unreadable = "servers:\n  - { name: s, kind: postgres, host: h, tls: verify_full, tls_ca_file: /nonexistent/ca.pem }\n";
    assert!(rejected(unreadable).to_string().contains("not readable"));

    let ca = tempfile::NamedTempFile::new().expect("temp ca");
    let ok = format!(
        "servers:\n  - {{ name: s, kind: postgres, host: h, tls: verify_full, tls_ca_file: {} }}\n",
        ca.path().display()
    );
    let config = ConfigFile::from_yaml_str(&ok).expect("verify_full with a CA parses");
    assert_eq!(config.servers[0].tls, crate::config::Tls::VerifyFull);
}

#[test]
fn permission_group_names_are_trimmed_on_load() {
    let yaml = with_server("permissions:\n  - { group: '  backend  ', grants: [] }\n");
    let config = ConfigFile::from_yaml_str(&yaml).expect("parses");
    assert_eq!(config.permissions[0].group, "backend");
}

/// `*` is the grant wildcard; a server or database literally named `*`
/// would alias it.
#[test]
fn rejects_server_or_database_named_wildcard() {
    for yaml in [
        "servers:\n  - { name: \"*\", kind: postgres, host: a }\n",
        "servers:\n  - name: prod\n    kind: postgres\n    host: a\n    databases:\n      - { name: \" * \", role: ro, password: x }\n",
    ] {
        let err = ConfigFile::from_yaml_str(yaml).expect_err("`*` name must reject");
        let ConfigFileError::Invalid(msg) = err else {
            panic!("expected Invalid, got {err:?}");
        };
        assert!(msg.contains("reserved for the grant wildcard"), "{msg}");
    }
}
