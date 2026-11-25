//! Connect-options construction and password resolution — the boundary
//! between YAML config and sqlx's `PgConnectOptions`.
//!
//! [`resolve_password`] is visible to sibling adapters
//! (`mongo::MongoAdapter::open`): the resolution rules are identical
//! regardless of backend, and the `ExecError` mapping is the same in every
//! call site. Re-exported at [`super`] so `super::pg::resolve_password`
//! keeps working from outside without leaking this submodule.

use secrecy::{ExposeSecret, SecretString};
use sqlx::ConnectOptions;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use crate::config::{Database, Password, Server, Tls};

use super::super::adapter::ExecError;

/// Options for connecting to `database` as `role` — the database's read
/// role or its write role; the two tiers differ in nothing else. Without a
/// password: that is resolved each time a tier opens ([`with_password`]).
pub(super) fn connect_options(
    server: &Server,
    database: &Database,
    role: &str,
) -> PgConnectOptions {
    let opts = PgConnectOptions::new()
        .host(&server.host)
        .port(server.port)
        .username(role)
        .database(database.connect_name())
        .ssl_mode(ssl_mode(server.tls))
        // No statement cache: the driver then prepares everything as the
        // unnamed statement, `prepare_with` included, which has no other
        // switch for it. A name would outlive its transaction in a
        // transaction-mode pooler that tracks statements by their text: the
        // next caller of that text is handed the old one, and after DDL the
        // server refuses it (`0A000`, see `error::is_stale_plan`).
        .statement_cache_capacity(0)
        // sqlx logs every statement it runs at `info` by default; on the
        // target path that is the caller's SQL — audit-row material, never a
        // log line.
        .disable_statement_logging();
    // Absent → the system roots verify the chain.
    match &server.tls_ca_file {
        Some(ca) => opts.ssl_root_cert(ca),
        None => opts,
    }
}

/// The sqlx boundary: the plaintext `&str` exists only for this builder
/// call, then lives inside `PgConnectOptions` (fed to the pool, dropped).
pub(super) fn with_password(
    options: PgConnectOptions,
    password: &SecretString,
) -> PgConnectOptions {
    options.password(password.expose_secret())
}

/// `required` encrypts without verifying (`sslmode=require`); only
/// `verify_full` checks the chain and the hostname.
fn ssl_mode(tls: Tls) -> PgSslMode {
    match tls {
        Tls::Required => PgSslMode::Require,
        Tls::VerifyFull => PgSslMode::VerifyFull,
        Tls::Insecure => PgSslMode::Disable,
    }
}

/// Adapt `Password::resolve` into `ExecError`. The boot-time walk in
/// `ConfigFile::resolve_secrets` already failed fast on every unresolvable
/// ref — but pools are opened lazily, so a `${FILE:…}` mount that disappears
/// after boot (rotation gone wrong) still needs a structured error here.
pub(crate) async fn resolve_password(password: &Password) -> Result<SecretString, ExecError> {
    use crate::config::SecretError;
    // `resolve_async`, not `resolve`: this runs on the request path when a
    // pool opens lazily, and the `${FILE:…}` arm would otherwise block the
    // runtime worker for the length of the read (#136).
    password.resolve_async().await.map_err(|err| match err {
        SecretError::EnvNotSet(name) | SecretError::EnvNotUtf8(name) => {
            ExecError::PasswordUnresolved {
                kind: "env",
                reference: name,
            }
        }
        SecretError::FileUnreadable { path, .. } | SecretError::FileEmpty(path) => {
            ExecError::PasswordUnresolved {
                kind: "file",
                reference: path.display().to_string(),
            }
        }
        // Keep the stable `(kind, reference)` tool-facing shape: `kind` is the
        // category, the scheme goes into `reference`. Emitting `kind: "vault"`
        // would force tool callers to match on every supported backend name.
        SecretError::BackendNotImplemented(scheme) => ExecError::PasswordUnresolved {
            kind: "backend",
            reference: scheme,
        },
        // Malformed refs are caught at YAML parse time, never reach here —
        // but stay structured rather than panic if invariants drift. No
        // payload is available (and intentionally so: the raw token could
        // be a typo'd plaintext password — see `SecretError::Malformed`).
        SecretError::Malformed => ExecError::PasswordUnresolved {
            kind: "malformed",
            reference: String::new(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every target pool — read, write and both cancel pools — opens with
    /// these options. The driver has no getter for the capacity.
    #[test]
    fn a_target_connection_never_names_a_statement() {
        let server: Server = serde_saphyr::from_str(
            "{name: s, kind: postgres, host: h, databases: [{name: d, role: r, password: p}]}",
        )
        .unwrap();
        let options = connect_options(&server, &server.databases[0], "r");
        let rendered = format!("{options:?}");
        assert!(
            rendered.contains("statement_cache_capacity: 0,"),
            "{rendered}"
        );
    }

    #[test]
    fn tls_maps_to_ssl_mode() {
        assert!(matches!(ssl_mode(Tls::Required), PgSslMode::Require));
        assert!(matches!(ssl_mode(Tls::VerifyFull), PgSslMode::VerifyFull));
        assert!(matches!(ssl_mode(Tls::Insecure), PgSslMode::Disable));
    }

    #[tokio::test]
    async fn resolve_password_handles_each_form() {
        assert_eq!(
            resolve_password(&Password::Literal("hunter2".into()))
                .await
                .unwrap()
                .expose_secret(),
            "hunter2"
        );

        let env_name = "DB_MCP_EXEC_TEST_PW";
        // SAFETY: test sets and clears a unique env var; nothing else reads it.
        unsafe {
            std::env::set_var(env_name, "from-env");
        }
        assert_eq!(
            resolve_password(&Password::EnvVar(env_name.into()))
                .await
                .unwrap()
                .expose_secret(),
            "from-env"
        );
        unsafe {
            std::env::remove_var(env_name);
        }
        assert!(matches!(
            resolve_password(&Password::EnvVar(env_name.into())).await,
            Err(ExecError::PasswordUnresolved { kind: "env", .. })
        ));

        // `kind: "backend"` keeps the tool-facing shape stable across
        // backends; the scheme rides along in `reference` so operators can
        // still tell vault from aws-sm in logs.
        match resolve_password(&Password::SecretBackend {
            scheme: "vault".into(),
            reference: "secret/path".into(),
        })
        .await
        {
            Err(ExecError::PasswordUnresolved { kind, reference }) => {
                assert_eq!(kind, "backend");
                assert_eq!(reference, "vault");
            }
            other => panic!("expected PasswordUnresolved {{ kind: backend, .. }}, got {other:?}"),
        }
    }
}
