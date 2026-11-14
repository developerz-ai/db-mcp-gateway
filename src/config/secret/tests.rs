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

/// Spec 08: an empty `${ENV:…}` aborts boot like an unset one, and the
/// error names the variable — the (empty) value has nothing to show.
#[test]
fn resolve_env_var_rejects_empty_value() {
    let name = format!("DB_MCP_SECRET_TEST_{}", uuid::Uuid::new_v4().simple());
    // SAFETY: unique name per test — nothing else reads it.
    unsafe {
        std::env::set_var(&name, "");
    }
    let result = Password::EnvVar(name.clone()).resolve();
    unsafe {
        std::env::remove_var(&name);
    }
    match result {
        Err(err @ SecretError::EnvNotSet(_)) => {
            assert!(format!("{err}").contains(&name), "{err}");
        }
        other => panic!("expected EnvNotSet for empty value, got {other:?}"),
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
