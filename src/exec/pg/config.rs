//! Connect-options construction and password resolution — the boundary
//! between YAML config and sqlx's `PgConnectOptions`.
//!
//! [`resolve_password`] is visible to sibling adapters
//! (`mongo::MongoAdapter::open`): the resolution rules are identical
//! regardless of backend, and the `ExecError` mapping is the same in every
//! call site. Re-exported at [`super`] so `super::pg::resolve_password`
//! keeps working from outside without leaking this submodule.

use secrecy::{ExposeSecret, SecretString};
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use crate::config::{Database, Password, Server, Tls};

use super::super::adapter::ExecError;

pub(super) fn build_connect_options(
    server: &Server,
    database: &Database,
    password: &SecretString,
) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&server.host)
        .port(server.port)
        .username(&database.role)
        // The sqlx boundary: the plaintext `&str` exists only for this builder
        // call, then lives inside `PgConnectOptions` (fed to the pool, dropped).
        .password(password.expose_secret())
        .database(&database.name)
        .ssl_mode(match server.tls {
            Tls::Required => PgSslMode::Require,
            Tls::Insecure => PgSslMode::Disable,
        })
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
