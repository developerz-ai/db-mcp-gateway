//! `mint-service-token`: the token it prints satisfies the boot validator,
//! and the YAML stanza carries a reference, never the value.

use db_mcp_gateway::auth::ServiceTokenStore;

use crate::cli_check::gateway;
use crate::common::gateway::config_file;

fn token_line(out: &str) -> &str {
    out.lines()
        .find_map(|line| line.strip_prefix("token (store this — shown once): "))
        .expect("token line")
}

#[test]
fn minted_token_passes_the_boot_validator() {
    let output = gateway(&["mint-service-token", "ci-bot"], &[]);
    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8(output.stdout).unwrap();
    let token = token_line(&out);
    let yaml = format!(
        "service_accounts:\n  - {{ name: ci-bot, group: svc-ci-bot, token: \"{token}\" }}\n\
         permissions:\n  - {{ group: svc-ci-bot, grants: [] }}\n"
    );
    let config = config_file(&yaml);
    ServiceTokenStore::from_config(&config.service_accounts).expect("boot accepts the token");
    let stanza = &out[out.find("service_accounts:").unwrap()..];
    assert!(
        stanza.contains("token: ${ENV:SERVICE_TOKEN_CI_BOT}"),
        "{stanza}"
    );
    assert!(!stanza.contains(token));
}

#[test]
fn bad_name_is_a_usage_error() {
    for name in ["", "CI", "a_b"] {
        let output = gateway(&["mint-service-token", name], &[]);
        assert_eq!(output.status.code(), Some(2), "{name:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("mint-service-token <name>"), "{stderr}");
    }
}
