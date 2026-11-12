//! Boot-time secret resolution acceptance test for #15.
//!
//! Two acceptance properties, taken straight from the issue:
//!   1. A config that references DB passwords via `${FILE:…}` mounts cleanly
//!      from a sealed-secret-style file on disk.
//!   2. A reference that can't resolve (env unset, file missing) aborts boot
//!      with a typed `SecretError` — never a silent first-query failure.
//!
//! Hits `ConfigFile::resolve_secrets` end-to-end through YAML parsing, so it
//! also defends the strict parse: legacy `${VAR}` (no scheme) is rejected at
//! parse time, not silently turned into a literal password.

mod common;

use db_mcp_gateway::config::{ConfigFile, ConfigFileError, Password, SecretError};
use db_mcp_gateway::exec::{Access, AdapterRegistry, ExecError, ExecQuery};
use db_mcp_gateway::state;
use std::io::Write;

fn yaml_with_password(reference: &str) -> String {
    format!(
        r#"
servers:
  - name: target
    kind: postgres
    description: Test
    host: localhost
    databases:
      - name: app
        role: ro
        password: {reference}
"#
    )
}

#[test]
fn file_reference_resolves_at_boot() {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    writeln!(file, "hunter2").unwrap();
    let path = file.path().display().to_string();

    let cfg = ConfigFile::from_yaml_str(&yaml_with_password(&format!("${{FILE:{path}}}")))
        .expect("YAML parses with FILE ref");

    // Sanity: the parsed Password is a File variant, not a literal.
    assert!(matches!(
        cfg.servers[0].databases[0].password,
        Password::File(_)
    ));

    // Boot-time walk succeeds — every ref resolves.
    cfg.resolve_secrets().expect("file ref resolves cleanly");
}

#[test]
fn env_reference_resolves_when_var_set() {
    let name = format!("DB_MCP_SECRET_E2E_{}", uuid::Uuid::new_v4().simple());
    // SAFETY: unique env var name per test run; nothing else reads or writes it.
    unsafe {
        std::env::set_var(&name, "from-env");
    }

    let cfg = ConfigFile::from_yaml_str(&yaml_with_password(&format!("${{ENV:{name}}}")))
        .expect("YAML parses with ENV ref");
    cfg.resolve_secrets().expect("env ref resolves cleanly");

    unsafe {
        std::env::remove_var(&name);
    }
}

#[test]
fn missing_env_aborts_boot_with_typed_error() {
    // Use a UUID-suffixed name so we don't accidentally collide with a real
    // var on the runner.
    let name = format!("DB_MCP_SECRET_MISSING_{}", uuid::Uuid::new_v4().simple());
    let cfg = ConfigFile::from_yaml_str(&yaml_with_password(&format!("${{ENV:{name}}}")))
        .expect("YAML parse succeeds — the ref is well-formed, just unset");

    match cfg.resolve_secrets() {
        Err(SecretError::EnvNotSet(n)) => assert_eq!(n, name),
        other => panic!("expected EnvNotSet(`{name}`), got {other:?}"),
    }
}

#[test]
fn missing_file_aborts_boot_with_typed_error() {
    let cfg = ConfigFile::from_yaml_str(&yaml_with_password(
        "${FILE:/nonexistent/db-mcp/secret-15-test}",
    ))
    .expect("YAML parse succeeds — well-formed FILE ref");

    match cfg.resolve_secrets() {
        Err(SecretError::FileUnreadable { path, .. }) => assert!(
            path.to_string_lossy().contains("secret-15-test"),
            "wrong path in error: {path:?}"
        ),
        other => panic!("expected FileUnreadable, got {other:?}"),
    }
}

#[test]
fn empty_file_aborts_boot() {
    // A zero-byte sealed-secret mount would otherwise auth-fail with an
    // empty password at first connect — a confusing operator signal.
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().display().to_string();

    let cfg = ConfigFile::from_yaml_str(&yaml_with_password(&format!("${{FILE:{path}}}")))
        .expect("YAML parses");

    assert!(matches!(
        cfg.resolve_secrets(),
        Err(SecretError::FileEmpty(_))
    ));
}

/// Legacy pre-#15 syntax (`${BARE_NAME}` without `ENV:` / `FILE:` scheme)
/// must be rejected at YAML parse time. If we silently treated it as a
/// literal password, an upgraded gateway would bind the string
/// `"${OLD_VAR}"` as the DB password and fail auth with a misleading error.
#[test]
fn legacy_braced_syntax_is_rejected_at_parse() {
    let err = ConfigFile::from_yaml_str(&yaml_with_password("${LEGACY_BARE_NAME}"))
        .expect_err("legacy ${VAR} must be rejected");

    // The error comes wrapped in the YAML parse layer (the Deserialize impl
    // for Password rejects malformed refs before we even reach resolve_secrets).
    assert!(
        matches!(err, ConfigFileError::Parse { .. }),
        "expected parse error, got {err:?}"
    );
}

/// Recognised secret-backend refs (`vault:`, `aws-sm:`, `gcp-sm:`) parse fine
/// but the resolve walk must abort boot: we don't ship backend integrations
/// yet, and silently passing the literal `vault:secret/...` as a password
/// would be a surprising auth failure later.
#[test]
fn unimplemented_backend_aborts_boot() {
    let cfg = ConfigFile::from_yaml_str(&yaml_with_password("vault:secret/prod/app_ro"))
        .expect("YAML parse succeeds");

    match cfg.resolve_secrets() {
        Err(SecretError::BackendNotImplemented(scheme)) => assert_eq!(scheme, "vault"),
        other => panic!("expected BackendNotImplemented(vault), got {other:?}"),
    }
}

/// C1 — A malformed / unreachable `STATE_DB_URL` must not leak the DSN or
/// password into the error message that the gateway would log or surface.
///
/// `StateDbError::Connect` wraps a `sqlx::Error` whose `Display` / `Debug`
/// *can* include the connection string on some sqlx versions. The gateway
/// intercepts the error in `boot_db_error` (main.rs) and emits only a
/// type-name + fixed string; this test verifies the public `Display` of
/// `StateDbError` itself is already safe, so no accidental `.to_string()`
/// call downstream can leak the credential.
#[tokio::test]
async fn malformed_state_db_url_leaks_no_dsn() {
    // Port 59999 is almost certainly not listening; the connection is refused
    // immediately rather than timing out, keeping the test fast.
    // "sentinelpassword" is the canary: if it appears in any formatted error
    // output the test fails.
    let url = "postgres://gateway:sentinelpassword@127.0.0.1:59999/gateway";
    let err = state::connect(url, std::num::NonZeroU32::MIN)
        .await
        .expect_err("connection to port 59999 must fail");

    // Must be the Connect variant, not Migrate (credentials only matter at connect).
    assert!(
        matches!(err, state::StateDbError::Connect(_)),
        "expected StateDbError::Connect, got {err:?}"
    );

    // Display is the string operators see in logs and error responses.
    let display = format!("{err}");
    // Debug is reachable via `{err:?}` in tracing macros or panic messages.
    let debug = format!("{err:?}");

    for forbidden in ["sentinelpassword", "59999", "gateway:sentinelpassword"] {
        assert!(
            !display.contains(forbidden),
            "DSN leaked in Display — `{forbidden}` found: {display}"
        );
        assert!(
            !debug.contains(forbidden),
            "DSN leaked in Debug — `{forbidden}` found: {debug}"
        );
    }
}

/// Password rotation without a restart (plan 101 slice 06): the password
/// file is rewritten after the pool opened, the old sessions are killed, and
/// the gateway picks up the new password — the adapter that saw the
/// credential rejection goes stale and the registry re-opens it, resolving
/// the file again. A dedicated role keeps the shared `app` role untouched.
#[tokio::test]
async fn rotated_password_file_is_picked_up_without_restart() {
    use common::pg_target;

    let probe = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "postgres://{}:{}@{}:{}/{}",
            pg_target::TARGET_USER,
            pg_target::TARGET_PASSWORD,
            pg_target::TARGET_HOST,
            pg_target::TARGET_PORT,
            pg_target::TARGET_DB
        ))
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let role = format!("rot_{}", uuid::Uuid::new_v4().simple());
    let set_password = |pw: &str| format!("ALTER ROLE \"{role}\" PASSWORD '{pw}'");
    sqlx::query(&format!("CREATE ROLE \"{role}\" LOGIN PASSWORD 'first-pw'"))
        .execute(&probe)
        .await
        .expect("create rotation role");

    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    write!(file, "first-pw").expect("write first password");
    let server = pg_target::server();
    let database = db_mcp_gateway::config::Database {
        role: role.clone(),
        password: Password::File(file.path().to_path_buf()),
        ..pg_target::database()
    };
    let registry = AdapterRegistry::new();
    let select_one = || ExecQuery {
        sql: "SELECT 1::int8 AS n",
        binds: &[],
        statement_timeout_ms: Some(5_000),
        row_limit: 1,
        access: Access::ReadOnly,
    };
    let run = |registry: AdapterRegistry| {
        let (server, database) = (server.clone(), database.clone());
        async move {
            let adapter = registry.get_or_open(&server, &database).await?;
            adapter.execute(select_one()).await
        }
    };

    run(registry.clone()).await.expect("first password works");

    sqlx::query(&set_password("second-pw"))
        .execute(&probe)
        .await
        .expect("rotate password");
    std::fs::write(file.path(), "second-pw").expect("rewrite password file");
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1")
        .bind(&role)
        .execute(&probe)
        .await
        .expect("kill the old sessions");

    // The first call after rotation may still try the old password on a new
    // connection; it marks the adapter stale. The next one must succeed.
    let first = run(registry.clone()).await;
    let second = run(registry.clone()).await;
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS \"{role}\""))
        .execute(&probe)
        .await;
    if let Err(err) = &first {
        assert!(
            matches!(err, ExecError::Connection | ExecError::Unavailable),
            "a failed first call is a credential/connection error, got {err:?}"
        );
    }
    second.expect("rotated password picked up without a restart");
}
