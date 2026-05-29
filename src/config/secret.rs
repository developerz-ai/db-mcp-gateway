//! Secret references in YAML config.
//!
//! Deliberately `Deserialize`-only: a `Password` MUST NOT round-trip back out
//! to a client response. Serializing it would defeat the whole point of having
//! credentials in this binary. Anything that goes over the wire uses
//! credential-free view types (see e.g. `tools::list_servers::SafeServerView`).
//!
//! Reference syntax (resolved at startup; see `Password::resolve`):
//!
//! - `${ENV:NAME}`  — value from the process environment
//! - `${FILE:/path}` — value read from a file (sealed-secret mount, ConfigMap, etc.)
//! - `vault:…`, `aws-sm:…`, `gcp-sm:…` — recognised but not implemented; the
//!   gateway aborts at boot rather than silently failing on first DB connect.
//! - any other string — taken as an inline literal (dev/test only).
//!
//! Any `${…}` payload that isn't `ENV:` or `FILE:` is rejected at parse time
//! so footguns like `${OLD_VAR_NAME}` (legacy syntax) don't silently become a
//! literal password.

use std::path::PathBuf;

use serde::Deserialize;

/// A secret reference as written in YAML. The variant tells us where the real
/// value lives; we resolve eagerly at startup.
///
/// `Debug` is hand-rolled to redact `Literal` plaintext — a derived `Debug`
/// would print the password verbatim, violating the no-creds-in-logs rule.
/// `EnvVar` / `File` / `SecretBackend` carry only references (env var names,
/// file paths, vault paths) which are safe to print and useful for diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub enum Password {
    /// Literal value inline in the YAML. Rejected in `env: production` by
    /// `Config::validate` (lands with issue #16's full validator).
    Literal(String),
    /// `${ENV:VAR_NAME}` — resolve from process env at startup.
    EnvVar(String),
    /// `${FILE:/run/secrets/foo}` — read from a file at startup. Trailing
    /// newlines are stripped (sealed-secrets / `printf > foo` both add one).
    File(PathBuf),
    /// `vault:secret/path`, `aws-sm:arn:...`, `gcp-sm:projects/...` — recognised
    /// schemes; backend resolution is not implemented in this build and the
    /// gateway aborts at startup rather than failing later.
    SecretBackend { scheme: String, reference: String },
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Password::Literal(_) => f.write_str("Literal(<redacted>)"),
            Password::EnvVar(name) => f.debug_tuple("EnvVar").field(name).finish(),
            Password::File(path) => f.debug_tuple("File").field(path).finish(),
            Password::SecretBackend { scheme, reference } => f
                .debug_struct("SecretBackend")
                .field("scheme", scheme)
                .field("reference", reference)
                .finish(),
        }
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Password::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// What can go wrong with a secret reference: at parse time (bad shape) or
/// at resolve time (env unset, file missing, backend not implemented).
///
/// `Display` carries the *reference* (env var name, file path) — that's
/// operationally useful and not itself a secret — but never the resolved
/// value.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("malformed secret reference `{0}`: expected `${{ENV:NAME}}` or `${{FILE:/path}}`")]
    Malformed(String),

    #[error("env var `{0}` referenced in config but not set in process environment")]
    EnvNotSet(String),

    #[error("env var `{0}` referenced in config holds an invalid UTF-8 value")]
    EnvNotUtf8(String),

    #[error("secret file `{path}` referenced in config could not be read")]
    FileUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("secret file `{0}` referenced in config is empty")]
    FileEmpty(PathBuf),

    #[error("secret backend `{0}` is not implemented in this build")]
    BackendNotImplemented(String),
}

impl Password {
    /// Parse a raw YAML string into a `Password`. Fails closed: any `${…}`
    /// payload that isn't `ENV:` or `FILE:` is rejected so legacy / typo
    /// references don't silently become literal passwords.
    pub fn parse(s: &str) -> Result<Self, SecretError> {
        if let Some(inner) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
            if let Some(name) = inner.strip_prefix("ENV:") {
                if name.is_empty() {
                    return Err(SecretError::Malformed(s.to_string()));
                }
                return Ok(Password::EnvVar(name.to_string()));
            }
            if let Some(path) = inner.strip_prefix("FILE:") {
                if path.is_empty() {
                    return Err(SecretError::Malformed(s.to_string()));
                }
                return Ok(Password::File(PathBuf::from(path)));
            }
            return Err(SecretError::Malformed(s.to_string()));
        }
        if let Some((scheme, reference)) = s.split_once(':') {
            // Only treat as a backend reference when the scheme is recognised.
            // A bare colon in a literal password (e.g. "abc:123") stays literal.
            match scheme {
                "vault" | "aws-sm" | "gcp-sm" => {
                    return Ok(Password::SecretBackend {
                        scheme: scheme.to_string(),
                        reference: reference.to_string(),
                    });
                }
                _ => {}
            }
        }
        Ok(Password::Literal(s.to_string()))
    }

    /// Resolve the reference to a plaintext password.
    ///
    /// Called both at boot (`config::validate_secrets`) to fail fast and
    /// again at pool-open time so credential rotation through file mounts
    /// works without a restart. The resolved value is moved into sqlx and
    /// dropped — it is never logged, never stored, never sent to a client.
    pub fn resolve(&self) -> Result<String, SecretError> {
        match self {
            Password::Literal(s) => Ok(s.clone()),
            Password::EnvVar(name) => match std::env::var(name) {
                Ok(v) => Ok(v),
                Err(std::env::VarError::NotPresent) => Err(SecretError::EnvNotSet(name.clone())),
                Err(std::env::VarError::NotUnicode(_)) => {
                    Err(SecretError::EnvNotUtf8(name.clone()))
                }
            },
            Password::File(path) => {
                let raw = std::fs::read_to_string(path).map_err(|source| {
                    SecretError::FileUnreadable {
                        path: path.clone(),
                        source,
                    }
                })?;
                // Sealed-secrets / `printf > file` / editors all leave a
                // trailing newline — strip CR/LF on both ends but preserve
                // anything an operator might have meaningfully padded with.
                let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
                if trimmed.is_empty() {
                    return Err(SecretError::FileEmpty(path.clone()));
                }
                Ok(trimmed)
            }
            Password::SecretBackend { scheme, .. } => {
                Err(SecretError::BackendNotImplemented(scheme.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn classifies_each_form() {
        assert_eq!(
            Password::parse("${ENV:STATE_DB_PW}").unwrap(),
            Password::EnvVar("STATE_DB_PW".into())
        );
        assert_eq!(
            Password::parse("${FILE:/run/secrets/db-pw}").unwrap(),
            Password::File(PathBuf::from("/run/secrets/db-pw"))
        );
        assert_eq!(
            Password::parse("vault:secret/prod/app_ro").unwrap(),
            Password::SecretBackend {
                scheme: "vault".into(),
                reference: "secret/prod/app_ro".into()
            }
        );
        assert_eq!(
            Password::parse("aws-sm:arn:aws:secretsmanager:...").unwrap(),
            Password::SecretBackend {
                scheme: "aws-sm".into(),
                reference: "arn:aws:secretsmanager:...".into()
            }
        );
        assert_eq!(
            Password::parse("hunter2").unwrap(),
            Password::Literal("hunter2".into())
        );
        // A bare colon in an unknown-scheme value stays literal.
        assert_eq!(
            Password::parse("not-a-scheme:hunter2").unwrap(),
            Password::Literal("not-a-scheme:hunter2".into())
        );
    }

    /// Legacy `${VAR}` syntax (#15 deprecates it) and bogus `${…}` payloads
    /// must NOT silently become literal passwords — that's a footgun that
    /// would silently bind the literal string as the DB password and fail
    /// auth at first connect with a misleading error.
    #[test]
    fn rejects_unknown_braced_payloads() {
        for bad in &[
            "${LEGACY_BARE_NAME}", // pre-#15 syntax
            "${env:lowercase}",    // scheme is case-sensitive
            "${ENV:}",             // empty name
            "${FILE:}",            // empty path
            "${OTHER:value}",      // unknown scheme
            "${}",                 // empty
        ] {
            assert!(
                matches!(Password::parse(bad), Err(SecretError::Malformed(_))),
                "expected `{bad}` to be rejected as malformed"
            );
        }
    }

    /// Defends the non-negotiable "no creds in logs/errors/responses":
    /// `format!("{:?}", literal)` must never print the plaintext.
    #[test]
    fn debug_redacts_literal_plaintext() {
        let literal = Password::Literal("hunter2".to_string());
        let rendered = format!("{literal:?}");
        assert!(
            !rendered.contains("hunter2"),
            "literal leaked via Debug: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "no redaction marker: {rendered}"
        );

        // References stay readable — useful in logs, not themselves secret.
        let env = Password::EnvVar("STATE_DB_PW".to_string());
        assert!(format!("{env:?}").contains("STATE_DB_PW"));
        let file = Password::File(PathBuf::from("/run/secrets/db-pw"));
        assert!(format!("{file:?}").contains("/run/secrets/db-pw"));
        let backend = Password::SecretBackend {
            scheme: "vault".into(),
            reference: "secret/prod/app_ro".into(),
        };
        let rendered = format!("{backend:?}");
        assert!(rendered.contains("vault"));
        assert!(rendered.contains("secret/prod/app_ro"));
    }

    #[test]
    fn resolve_literal_returns_inline_value() {
        let p = Password::Literal("hunter2".to_string());
        assert_eq!(p.resolve().unwrap(), "hunter2");
    }

    #[test]
    fn resolve_env_var_reads_process_env_or_errors_clearly() {
        // Unique name per test so parallel runs don't trample each other.
        let name = format!("DB_MCP_SECRET_TEST_{}", uuid::Uuid::new_v4().simple());

        // Unset → clear typed error carrying the var name.
        let p = Password::EnvVar(name.clone());
        match p.resolve() {
            Err(SecretError::EnvNotSet(n)) => assert_eq!(n, name),
            other => panic!("expected EnvNotSet, got {other:?}"),
        }

        // SAFETY: unique name per test — nothing else reads it.
        unsafe {
            std::env::set_var(&name, "from-env");
        }
        assert_eq!(p.resolve().unwrap(), "from-env");
        unsafe {
            std::env::remove_var(&name);
        }
    }

    #[test]
    fn resolve_file_reads_value_and_strips_trailing_newline() {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(file, "hunter2").unwrap();
        let p = Password::File(file.path().to_path_buf());
        assert_eq!(p.resolve().unwrap(), "hunter2");
    }

    #[test]
    fn resolve_file_missing_returns_typed_error_with_path() {
        let p = Password::File(PathBuf::from("/nonexistent/db-mcp/secret"));
        match p.resolve() {
            Err(SecretError::FileUnreadable { path, .. }) => {
                assert_eq!(path, PathBuf::from("/nonexistent/db-mcp/secret"));
            }
            other => panic!("expected FileUnreadable, got {other:?}"),
        }
    }

    #[test]
    fn resolve_file_empty_is_rejected() {
        // A zero-byte mount is almost certainly a misconfigured sealed-secret
        // — bind it as the DB password and you'd silently auth-fail with an
        // empty string. Refuse at boot.
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let p = Password::File(file.path().to_path_buf());
        assert!(matches!(p.resolve(), Err(SecretError::FileEmpty(_))));
    }

    #[test]
    fn resolve_secret_backend_errors_until_implemented() {
        let p = Password::SecretBackend {
            scheme: "vault".into(),
            reference: "secret/path".into(),
        };
        match p.resolve() {
            Err(SecretError::BackendNotImplemented(s)) => assert_eq!(s, "vault"),
            other => panic!("expected BackendNotImplemented, got {other:?}"),
        }
    }

    /// Defends the no-creds-in-Display rule across every error variant.
    #[test]
    fn errors_never_print_resolved_plaintext() {
        let cases = [
            SecretError::Malformed("${weird}".into()),
            SecretError::EnvNotSet("MY_VAR".into()),
            SecretError::EnvNotUtf8("MY_VAR".into()),
            SecretError::FileEmpty(PathBuf::from("/run/secrets/x")),
            SecretError::BackendNotImplemented("vault".into()),
        ];
        for err in cases {
            let rendered = format!("{err}");
            for forbidden in ["hunter2", "from-env"] {
                assert!(
                    !rendered.contains(forbidden),
                    "leaked `{forbidden}` in: {rendered}"
                );
            }
        }
    }
}
