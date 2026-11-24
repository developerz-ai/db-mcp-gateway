//! `--check` golden output: the real binary, a cleared environment, the
//! fixtures in `tests/data/check/`. Regenerate the `.out` files with
//! `UPDATE_GOLDEN=1 cargo test --test it_offline cli_check::` and review the
//! diff.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES: &str = "tests/data/check";

/// Run the gateway binary from the package root with only `env` set.
pub fn gateway(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_db-mcp-gateway"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run the gateway binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 stdout")
}

fn check(fixture: &str, extra: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let path = format!("{FIXTURES}/{fixture}.yaml");
    let mut args = vec!["--config", path.as_str(), "--check"];
    args.extend_from_slice(extra);
    // `from_env` needs TLS settled to load; the state DB default applies.
    let mut env = env.to_vec();
    env.push(("TLS_DISABLED", "true"));
    let output = gateway(&args, &env);
    (output.status.code().expect("exit code"), stdout(&output))
}

fn assert_golden(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES)
        .join(format!("{name}.out"));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{}: {err} (UPDATE_GOLDEN=1 writes it)", golden(&path)));
    assert_eq!(actual, expected, "{} differs", golden(&path));
}

fn golden(path: &Path) -> String {
    path.display().to_string()
}

/// `--config` from the flag or `DB_MCP_GATEWAY_CONFIG`, the flag winning;
/// neither is a usage error. Each case is its own process environment.
#[test]
fn config_comes_from_the_flag_or_the_env_var() {
    let good = format!("{FIXTURES}/good.yaml");
    let other = format!("{FIXTURES}/warnings.yaml");
    let env = [
        ("TLS_DISABLED", "true"),
        ("DB_MCP_GATEWAY_CONFIG", good.as_str()),
    ];
    let from_env = stdout(&gateway(&["--check", "--no-secrets"], &env));
    assert!(
        from_env.starts_with(&format!("config: {good}\n")),
        "{from_env}"
    );
    let flag_wins = stdout(&gateway(
        &["--config", &other, "--check", "--no-secrets"],
        &env,
    ));
    assert!(
        flag_wins.starts_with(&format!("config: {other}\n")),
        "{flag_wins}"
    );
    let neither = gateway(&["--check"], &[("TLS_DISABLED", "true")]);
    assert_eq!(neither.status.code(), Some(2), "{neither:?}");
}

#[test]
fn valid_config_without_secrets_passes() {
    let (code, out) = check("good", &["--no-secrets"], &[]);
    assert_golden("good.no-secrets", &out);
    assert_eq!(code, 0, "{out}");
}

/// Every unresolved reference is reported, each naming server, database and
/// tier — not just the first.
#[test]
fn unresolved_secrets_are_all_reported_with_their_site() {
    let (code, out) = check("good", &[], &[]);
    assert_golden("good.secrets", &out);
    assert_eq!(code, 1, "{out}");
}

/// `${ENV:…}` is the credential byte for byte (only `${FILE:…}` trims): a
/// value with a trailing newline, even one that is only a newline, resolves.
#[test]
fn env_values_are_used_byte_for_byte() {
    let (code, out) = check(
        "good",
        &[],
        &[
            ("CHECK_APP_RO_PASSWORD", "\n"),
            ("CHECK_CACHE_PASSWORD", "cache-pw\r\n"),
        ],
    );
    // The fixture's write tier is a `${FILE:…}` that does not exist.
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("write_password (write tier)"), "{out}");
    assert!(!out.contains("CHECK_APP_RO_PASSWORD"), "{out}");
    assert!(!out.contains("CHECK_CACHE_PASSWORD"), "{out}");
}

#[test]
fn warnings_name_tls_inert_constraints_and_unknown_env() {
    let env = [
        ("CHECK_APP_RO_PASSWORD", "set"),
        ("TLS_CERT", "/etc/tls/cert.pem"),
        ("OIDC_ISUER", "https://idp.example.com"),
        ("UNRELATED_VARIABLE", "x"),
    ];
    let (code, out) = check("warnings", &["--no-secrets"], &env);
    assert_golden("warnings", &out);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("/etc/tls/cert.pem"), "env values never print");
}

/// All independent mistakes in one run; the pasted-password `role` and the
/// production literal are named by field, never echoed.
#[test]
fn invalid_config_reports_every_error_without_values() {
    let (code, out) = check("invalid", &["--no-secrets"], &[]);
    assert_golden("invalid", &out);
    assert_eq!(code, 1, "{out}");
    for secret in ["S3cr3t", "literal-in-production"] {
        assert!(!out.contains(secret), "{secret} leaked:\n{out}");
    }
}

#[test]
fn parse_error_names_position_and_schema_never_the_value() {
    let (code, out) = check("parse_error", &["--no-secrets"], &[]);
    assert_golden("parse_error", &out);
    assert_eq!(code, 1, "{out}");
    assert!(!out.contains("hunter2"), "{out}");
}

/// The boot path aggregates the same way: one abort lists every error.
#[test]
fn boot_reports_every_config_error_at_once() {
    let output = gateway(
        &["--config", &format!("{FIXTURES}/invalid.yaml")],
        &[("TLS_DISABLED", "true")],
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("7 config errors"), "{stderr}");
    assert!(!stderr.contains("S3cr3t"), "{stderr}");
}

#[test]
fn healthcheck_fails_when_nothing_listens() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("ephemeral port")
        .port();
    let bind = format!("127.0.0.1:{port}");
    let output = gateway(
        &["--healthcheck"],
        &[("GATEWAY_BIND", &bind), ("TLS_DISABLED", "true")],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(stdout(&output).starts_with("unhealthy:"));
}

/// #397: `--check` runs boot's env parsers and names every variable set to a
/// value boot refuses — never the value. `--no-secrets` does not skip it.
#[test]
fn invalid_environment_is_reported_by_name_only() {
    let env = [
        ("GROUPS_MAX_AGE", "30x"),
        ("SESSION_CACHE_TTL_SECONDS", "soon-hunter2"),
        ("METRICS_BIND", "nowhere-hunter2"),
        ("TRUSTED_PROXIES", "10.0.0.0/99"),
        ("PG_CANCEL_POOL_SIZE", "990099"),
        ("SESSION_TTL_HOURS", "999999"),
        ("ALLOW_INSECURE_SIGNING_KEY", "maybe"),
        ("STATE_DB_CONNECT_TIMEOUT_SECONDS", "forever"),
    ];
    let (code, out) = check("good", &["--no-secrets"], &env);
    assert_golden("env_invalid", &out);
    assert_eq!(code, 1, "{out}");
    for (_, value) in env {
        assert!(!out.contains(value), "{value} leaked:\n{out}");
    }
}

#[test]
fn invalid_groups_max_age_fails_the_check() {
    let (code, out) = check("good", &["--no-secrets"], &[("GROUPS_MAX_AGE", "30x")]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("error: environment variable GROUPS_MAX_AGE:"),
        "{out}"
    );
    assert!(!out.contains("30x"), "{out}");
}

/// A valid deployment environment changes nothing: same output as none.
#[test]
fn valid_environment_leaves_the_output_unchanged() {
    let env = [
        ("GROUPS_MAX_AGE", "12h"),
        ("OIDC_SCOPES", "openid email groups"),
        ("OIDC_TOKEN_AUTH_METHOD", "client_secret_basic"),
        ("SESSION_TTL_HOURS", "8"),
        ("REFRESH_TTL_DAYS", "30"),
        ("TRUSTED_PROXIES", "10.0.0.0/8"),
        ("MCP_ALLOWED_ORIGINS", "https://app.example.com"),
        ("METRICS_BIND", "0.0.0.0:9090"),
        ("MAX_CONCURRENT_REQUESTS", "256"),
        ("PG_CANCEL_POOL_SIZE", "2"),
        ("STATE_DB_CONNECT_TIMEOUT_SECONDS", "30"),
    ];
    let (code, out) = check("good", &["--no-secrets"], &env);
    assert_golden("good.no-secrets", &out);
    assert_eq!(code, 0, "{out}");
}

/// Required-but-unset settings belong to the deployment, not to the value
/// check: CI runs `--check` without the TLS paths or the IdP.
#[test]
fn unset_required_variables_are_not_errors() {
    let path = format!("{FIXTURES}/good.yaml");
    let output = gateway(&["--config", &path, "--check", "--no-secrets"], &[]);
    let out = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{out}");
    assert!(!out.contains("error:"), "{out}");
}
