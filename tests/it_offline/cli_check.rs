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

/// `${ENV:…}` is trimmed of its trailing newline like `${FILE:…}`: a value
/// that is only a newline is empty, one with a trailing newline resolves.
#[test]
fn env_values_are_trimmed_like_file_values() {
    let (code, out) = check(
        "good",
        &[],
        &[
            ("CHECK_APP_RO_PASSWORD", "\n"),
            ("CHECK_CACHE_PASSWORD", "cache-pw\r\n"),
        ],
    );
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(
            "error: servers[prod].databases[app].password (read tier): env var \
             `CHECK_APP_RO_PASSWORD` referenced in config is unset or empty"
        ),
        "{out}"
    );
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
