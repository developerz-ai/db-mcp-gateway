//! Secret references in YAML config.
//!
//! Deliberately `Deserialize`-only: a `Password` MUST NOT round-trip back out
//! to a client response. Serializing it would defeat the whole point of having
//! credentials in this binary. Anything that goes over the wire uses
//! credential-free view types (see e.g. `tools::list_servers::SafeServerView`).
//!
//! Resolution happens twice: once at boot so an unresolvable ref fails fast,
//! and again when a pool opens lazily, so rotating a file-mounted secret does
//! not need a restart. Use [`Password::resolve`] on the boot path and
//! [`Password::resolve_async`] on the request path — the latter keeps a slow
//! secret mount from parking a runtime worker thread.
//!
//! Reference syntax:
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

use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Deserialize;
use zeroize::Zeroizing;

/// A secret reference as written in YAML. The variant tells us where the real
/// value lives; we resolve eagerly at startup.
///
/// `Debug` is hand-rolled to redact `Literal` plaintext — a derived `Debug`
/// would print the password verbatim, violating the no-creds-in-logs rule.
/// `EnvVar` / `File` / `SecretBackend` carry only references (env var names,
/// file paths, vault paths) which are safe to print and useful for diagnostics.
///
/// No `PartialEq`/`Eq`: `SecretString` deliberately omits them so passwords are
/// never compared with `==` (non-constant-time, easy to leak). Tests match on
/// the variant and compare the exposed inner explicitly.
#[derive(Clone)]
pub enum Password {
    /// Literal value inline in the YAML, held in a `SecretString` so it zeroes
    /// on drop and can't be `Debug`-printed in the clear. Rejected in
    /// `env: production` by `Config::validate` (lands with issue #16's full
    /// validator).
    Literal(SecretString),
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
    // No payload: a typo like `${hunter2}` would otherwise echo the
    // (likely-literal) plaintext into a boot error / log, breaking the
    // no-secrets-in-errors invariant. Operators get the shape-hint they need
    // from the message; the actual offending bytes stay inside the config.
    #[error("malformed secret reference: expected `${{ENV:NAME}}` or `${{FILE:/path}}`")]
    Malformed,

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
                    return Err(SecretError::Malformed);
                }
                return Ok(Password::EnvVar(name.to_string()));
            }
            if let Some(path) = inner.strip_prefix("FILE:") {
                if path.is_empty() {
                    return Err(SecretError::Malformed);
                }
                return Ok(Password::File(PathBuf::from(path)));
            }
            return Err(SecretError::Malformed);
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
        Ok(Password::Literal(SecretString::from(s)))
    }

    /// Resolve the reference to a plaintext password.
    ///
    /// Called both at boot (`config::validate_secrets`) to fail fast and
    /// again at pool-open time so credential rotation through file mounts
    /// works without a restart. The returned `SecretString` zeroes its heap
    /// buffer on drop and refuses to `Debug`-print in the clear; callers
    /// expose `&str` only at the driver boundary (`PgConnectOptions::password`,
    /// mongo's `Credential`). It is never logged, never stored, never sent to a
    /// client.
    pub fn resolve(&self) -> Result<SecretString, SecretError> {
        match self {
            Password::Literal(s) => Ok(s.clone()),
            Password::EnvVar(name) => match std::env::var(name) {
                Ok(v) => Ok(SecretString::from(v)),
                Err(std::env::VarError::NotPresent) => Err(SecretError::EnvNotSet(name.clone())),
                Err(std::env::VarError::NotUnicode(_)) => {
                    Err(SecretError::EnvNotUtf8(name.clone()))
                }
            },
            Password::File(path) => {
                // Read into a `Zeroizing` buffer so the full file contents —
                // including any trailing bytes we trim away — are wiped from
                // the heap on drop, not just the trimmed secret we hand back.
                let raw = Zeroizing::new(std::fs::read_to_string(path).map_err(|source| {
                    SecretError::FileUnreadable {
                        path: path.clone(),
                        source,
                    }
                })?);
                Self::secret_from_file_contents(&raw, path)
            }
            Password::SecretBackend { scheme, .. } => {
                Err(SecretError::BackendNotImplemented(scheme.clone()))
            }
        }
    }

    /// Async twin of [`Self::resolve`], for callers on the request path.
    ///
    /// Only the `File` variant differs: [`Self::resolve`] reads it with
    /// `std::fs`, which parks the whole runtime worker thread for the duration
    /// of the syscall. Pools open lazily on the first request to a database
    /// (`PgAdapter::open` → `resolve_password`), so that blocking read sits on
    /// an async task — and a slow or hung secret mount (NFS, a CSI driver
    /// re-materializing a rotated secret) stalls every other task scheduled on
    /// that worker, not just this one (#136). The other variants touch no
    /// filesystem — `EnvVar` reads process memory — so they delegate.
    pub async fn resolve_async(&self) -> Result<SecretString, SecretError> {
        let Password::File(path) = self else {
            return self.resolve();
        };
        let raw = Zeroizing::new(tokio::fs::read_to_string(path).await.map_err(|source| {
            SecretError::FileUnreadable {
                path: path.clone(),
                source,
            }
        })?);
        Self::secret_from_file_contents(&raw, path)
    }

    /// Shared tail of both read paths, so the trimming and empty-file rules
    /// can't drift between them.
    fn secret_from_file_contents(raw: &str, path: &Path) -> Result<SecretString, SecretError> {
        // Sealed-secrets / `printf > file` / editors all leave a trailing
        // newline — strip CR/LF on both ends but preserve anything an operator
        // might have meaningfully padded with.
        let trimmed = raw.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            return Err(SecretError::FileEmpty(path.to_path_buf()));
        }
        Ok(SecretString::from(trimmed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn classifies_each_form() {
        // `Password` has no `PartialEq` (see the type doc) — match on the
        // variant and compare the inner reference / exposed secret explicitly.
        assert!(matches!(
            Password::parse("${ENV:STATE_DB_PW}").unwrap(),
            Password::EnvVar(name) if name == "STATE_DB_PW"
        ));
        assert!(matches!(
            Password::parse("${FILE:/run/secrets/db-pw}").unwrap(),
            Password::File(path) if path == Path::new("/run/secrets/db-pw")
        ));
        assert!(matches!(
            Password::parse("vault:secret/prod/app_ro").unwrap(),
            Password::SecretBackend { scheme, reference }
                if scheme == "vault" && reference == "secret/prod/app_ro"
        ));
        assert!(matches!(
            Password::parse("aws-sm:arn:aws:secretsmanager:...").unwrap(),
            Password::SecretBackend { scheme, reference }
                if scheme == "aws-sm" && reference == "arn:aws:secretsmanager:..."
        ));
        assert!(matches!(
            Password::parse("hunter2").unwrap(),
            Password::Literal(s) if s.expose_secret() == "hunter2"
        ));
        // A bare colon in an unknown-scheme value stays literal.
        assert!(matches!(
            Password::parse("not-a-scheme:hunter2").unwrap(),
            Password::Literal(s) if s.expose_secret() == "not-a-scheme:hunter2"
        ));
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
                matches!(Password::parse(bad), Err(SecretError::Malformed)),
                "expected `{bad}` to be rejected as malformed"
            );
        }
    }

    /// Defends the non-negotiable "no creds in logs/errors/responses":
    /// `format!("{:?}", literal)` must never print the plaintext.
    #[test]
    fn debug_redacts_literal_plaintext() {
        let literal = Password::Literal("hunter2".into());
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
        let p = Password::Literal("hunter2".into());
        assert_eq!(p.resolve().unwrap().expose_secret(), "hunter2");
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
        assert_eq!(p.resolve().unwrap().expose_secret(), "from-env");
        unsafe {
            std::env::remove_var(&name);
        }
    }

    #[test]
    fn resolve_file_reads_value_and_strips_trailing_newline() {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(file, "hunter2").unwrap();
        let p = Password::File(file.path().to_path_buf());
        assert_eq!(p.resolve().unwrap().expose_secret(), "hunter2");
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
    /// Includes a `Malformed` case to defend the no-payload contract: even if
    /// a typo'd ref were the literal plaintext (e.g. `${hunter2}`), the error
    /// message must not echo it back.
    #[test]
    fn errors_never_print_resolved_plaintext() {
        let cases = [
            SecretError::Malformed,
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

    /// `resolve_async` is what the request path uses; it must agree with the
    /// sync twin on every variant, including the trimming and empty-file rules
    /// they now share.
    #[tokio::test]
    async fn resolve_async_matches_resolve_on_every_variant() {
        use secrecy::ExposeSecret;

        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        // Trailing newline is the common sealed-secret / `printf >` shape.
        writeln!(f, "s3cr3t").expect("write secret");
        let file_ref = Password::File(f.path().to_path_buf());
        assert_eq!(
            file_ref
                .resolve_async()
                .await
                .expect("async read")
                .expose_secret(),
            file_ref.resolve().expect("sync read").expose_secret(),
            "async and sync file reads must agree, newline trimming included"
        );
        assert_eq!(
            file_ref
                .resolve_async()
                .await
                .expect("async read")
                .expose_secret(),
            "s3cr3t"
        );

        // Non-file variants touch no filesystem and simply delegate.
        let literal = Password::Literal("hunter2".into());
        assert_eq!(
            literal
                .resolve_async()
                .await
                .expect("literal")
                .expose_secret(),
            "hunter2"
        );

        // An empty file is still an error on the async path.
        let empty = tempfile::NamedTempFile::new().expect("temp file");
        let empty_ref = Password::File(empty.path().to_path_buf());
        assert!(matches!(
            empty_ref.resolve_async().await,
            Err(SecretError::FileEmpty(_))
        ));

        // And a missing file surfaces as unreadable, not as a panic.
        let missing = Password::File(PathBuf::from("/nonexistent/db-mcp-secret"));
        assert!(matches!(
            missing.resolve_async().await,
            Err(SecretError::FileUnreadable { .. })
        ));
    }
}
