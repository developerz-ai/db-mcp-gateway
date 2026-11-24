use std::path::{Path, PathBuf};

use clap::Parser;

use super::check::env_names::{GATEWAY_ENV_PREFIXES, KNOWN_ENV};
use super::{Action, Cli, Command, Tool};

const ENV: &str = "DB_MCP_GATEWAY_CONFIG";

fn action(args: &[&str]) -> Action {
    Cli::try_parse_from(args).unwrap().into_action().unwrap()
}

/// `--config` is required to serve, from the flag or the env var, the flag
/// winning. One test, so nothing races on the shared env var (clap reads it
/// at parse time); no other test in this binary touches it.
#[test]
fn serve_requires_config_with_env_fallback() {
    // SAFETY: this test is the sole reader/writer of $ENV in this binary.
    unsafe { std::env::remove_var(ENV) };
    assert!(Cli::try_parse_from(["db-mcp-gateway"]).is_err());
    assert!(matches!(
        action(&["db-mcp-gateway", "--config", "/tmp/flag.yaml"]),
        Action::Serve(path) if path == Path::new("/tmp/flag.yaml")
    ));
    unsafe { std::env::set_var(ENV, "/tmp/from-env.yaml") };
    assert!(matches!(
        action(&["db-mcp-gateway"]),
        Action::Serve(path) if path == Path::new("/tmp/from-env.yaml")
    ));
    assert!(matches!(
        action(&["db-mcp-gateway", "--config", "/tmp/flag-wins.yaml"]),
        Action::Serve(path) if path == Path::new("/tmp/flag-wins.yaml")
    ));
    unsafe { std::env::remove_var(ENV) };

    // Neither the probe nor a subcommand needs the serve config.
    assert!(matches!(
        action(&["db-mcp-gateway", "--healthcheck"]),
        Action::Tool(Tool::Healthcheck)
    ));
    assert!(matches!(
        action(&["db-mcp-gateway", "mint-service-token", "ci-bot"]),
        Action::Tool(Tool::Command(Command::MintServiceToken(_)))
    ));
}

#[test]
fn check_flags_parse_and_no_secrets_needs_check() {
    assert!(matches!(
        action(&[
            "db-mcp-gateway",
            "--config",
            "c.yaml",
            "--check",
            "--no-secrets"
        ]),
        Action::Tool(Tool::Check {
            no_secrets: true,
            ..
        })
    ));
    assert!(Cli::try_parse_from(["db-mcp-gateway", "--config", "c.yaml", "--no-secrets"]).is_err());
    assert!(
        Cli::try_parse_from([
            "db-mcp-gateway",
            "--config",
            "c",
            "--check",
            "--healthcheck"
        ])
        .is_err()
    );
}

/// The unknown-env warning is only as good as this list: it must hold every
/// variable the deployment docs say the gateway reads.
#[test]
fn known_env_covers_the_documented_table() {
    let doc = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("website/docs/deployment/quickstart.md"),
    )
    .unwrap();
    let heading = "### The environment variables the gateway reads";
    let section = &doc[doc.find(heading).unwrap() + heading.len()..];
    let section = &section[..section.find("\n#").unwrap_or(section.len())];
    let documented: Vec<&str> = section
        .lines()
        .filter(|line| line.starts_with("| `"))
        .filter_map(|line| line.split('|').nth(1))
        .flat_map(|cell| cell.split('`').skip(1).step_by(2))
        .collect();
    assert!(documented.len() > 20, "env table not found");
    for name in documented {
        assert!(KNOWN_ENV.contains(&name), "{name}: add it to KNOWN_ENV");
    }
    for prefix in GATEWAY_ENV_PREFIXES {
        assert!(
            KNOWN_ENV.iter().any(|name| name.starts_with(prefix)),
            "{prefix}: no known variable has this prefix"
        );
    }
}
