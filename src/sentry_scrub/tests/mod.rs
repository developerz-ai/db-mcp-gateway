//! No network, no real DB. Scrubber is pure string work, and DSN parsing
//! is exercised via the pure [`parse_dsn`] helper → no test mutates the
//! process env → parallel-safe.
//!
//! These run under `cargo test`, whose dependency graph includes
//! dev-dependencies and therefore more `regex` features than the shipping
//! binary gets. That is exactly how the fail-closed bug stayed green here
//! while production redacted every event, so the *feature* half of this
//! contract is enforced outside cargo test, by `bin/lint`.

mod event_fields;

use super::*;

fn scrubber() -> Scrubber {
    Scrubber::new().expect("scrubber patterns compile")
}

#[test]
fn scrubs_postgres_dsn_in_event_message() {
    let secret = "app-dev-only";
    let mut event = sentry::protocol::Event {
        message: Some(format!(
            "connect postgres://app:{secret}@localhost:5434/app failed"
        )),
        ..sentry::protocol::Event::default()
    };
    // Same secret nested in `extra` JSON must also be caught by recursion.
    event.extra.insert(
        "ctx".to_owned(),
        serde_json::json!({ "url": format!("postgresql://app:{secret}@db:5432/x") }),
    );

    let scrubbed = scrubber()
        .scrub_event(event)
        .expect("scrubber always returns Some");
    let msg = scrubbed.message.as_deref().expect("message preserved");
    assert!(msg.contains("***REDACTED***"), "message redacted: {msg}");
    assert!(!msg.contains(secret), "password leaked into message: {msg}");

    let extra = scrubbed.extra.get("ctx").expect("extra preserved");
    let json = extra.to_string();
    assert!(json.contains("***REDACTED***"), "nested extra redacted");
    assert!(!json.contains(secret), "secret in nested extra");
}

#[test]
fn scrubs_password_assignment() {
    let scrubber = scrubber();

    // `key=value` form (the contract under test).
    let out = scrubber.scrub_str("password=hunter2 ok");
    assert!(out.contains("***REDACTED***"), "{out}");
    assert!(!out.contains("hunter2"), "{out}");

    // `key: value` form, mixed case.
    let out = scrubber.scrub_str("OIDC_CLIENT_SECRET: s3cr3t-value");
    assert!(out.contains("***REDACTED***"), "{out}");
    assert!(!out.contains("s3cr3t-value"), "{out}");

    // Allowlisted env names: value redacted even with no `user:pass@`
    // userinfo and no secret keyword. The internal hostname must not leak.
    // (CodeRabbit: SESSION_SIGNING_KEY / STATE_DB_URL bypassed the old
    // scrubber.)
    let out = scrubber.scrub_str("SESSION_SIGNING_KEY=jwt-hs256-base64-secret");
    assert!(out.contains("***REDACTED***"), "{out}");
    assert!(!out.contains("jwt-hs256-base64-secret"), "{out}");

    let out = scrubber.scrub_str("STATE_DB_URL=postgres://db.internal/app");
    assert!(out.contains("***REDACTED***"), "{out}");
    assert!(
        !out.contains("db.internal"),
        "internal hostname leaked: {out}"
    );

    // A userinfo-bearing STATE_DB_URL is also fully redacted (allowlist
    // whole-value pass, not just the URL userinfo strip).
    let out = scrubber.scrub_str("STATE_DB_URL=postgres://app:s3cr3t@db.internal/app");
    assert!(out.contains("***REDACTED***"), "{out}");
    assert!(!out.contains("s3cr3t"), "{out}");
    assert!(!out.contains("db.internal"), "{out}");

    // `: value` separator, mixed case, and a sibling non-sensitive key
    // left intact.
    let out = scrubber.scrub_str("state_db_url: postgres://db.internal/app ok=1");
    assert!(out.contains("***REDACTED***"), "{out}");
    assert!(out.contains("ok=1"), "benign sibling key clobbered: {out}");

    // `MY_STATE_DB_URL` is not the allowlisted key — left alone by this
    // pass (its value carries no creds here).
    let out = scrubber.scrub_str("MY_STATE_DB_URL=harmless");
    assert!(!out.contains("***REDACTED***"), "false positive: {out}");

    // Each DB scheme family loses its userinfo, host stays.
    for raw in [
        "postgres://u:p@h/db",
        "postgresql://u:p@h:5432/db",
        "mysql://u:p@h/db",
        "mongodb://u:p@h/db",
        "mongodb+srv://u:p@cluster.h/db",
        "mariadb://u:p@h/db",
        "redis://u:p@h:6379",
    ] {
        let out = scrubber.scrub_str(raw);
        assert!(out.contains("***REDACTED***"), "{raw} -> {out}");
        assert!(!out.contains(":p@"), "userinfo leaked: {raw} -> {out}");
    }
}

#[test]
fn does_not_redact_benign_text() {
    let scrubber = scrubber();
    // No creds, no secret keys → untouched.
    let raw = "query returned 42 rows from table users in 3ms";
    assert_eq!(scrubber.scrub_str(raw), raw);
    // A URL without credentials is left intact.
    let raw = "see https://example.com/docs for details";
    assert_eq!(scrubber.scrub_str(raw), raw);
}

/// The production regression (GlitchTip issue DB-MCP-GATEWAY-2, 40 events,
/// every one titled `***REDACTED***: ***REDACTED***`): the whole string
/// must never collapse to the sentinel. A scrubber that redacts everything
/// leaks nothing but tells nobody anything, and every distinct error
/// fingerprints into one unreadable issue.
#[test]
fn benign_error_text_never_collapses_to_the_sentinel() {
    let scrubber = scrubber();
    let boot_error = "state DB: failed to connect (pool_timed_out; DSN withheld)";

    let mut event = sentry::protocol::Event::default();
    event.exception.values.push(sentry::protocol::Exception {
        ty: "Error".to_owned(),
        value: Some(boot_error.to_owned()),
        ..Default::default()
    });

    let scrubbed = scrubber.scrub_event(event).expect("Some");
    let ex = &scrubbed.exception.values[0];
    assert_eq!(ex.ty, "Error", "exception type replaced wholesale");
    assert_eq!(
        ex.value.as_deref(),
        Some(boot_error),
        "exception value replaced wholesale"
    );
}

#[test]
fn scrubs_exception_value_and_type() {
    let mut event = sentry::protocol::Event::default();
    event.exception.values.push(sentry::protocol::Exception {
        ty: "ConnectError postgres://u:leak-me@h/db".to_owned(),
        value: Some("dsn=postgres://u:leak-me@h/db".into()),
        ..Default::default()
    });

    let scrubbed = scrubber().scrub_event(event).expect("Some");
    let ex = &scrubbed.exception.values[0];
    assert!(!ex.ty.contains("leak-me"), "type leaked: {}", ex.ty);
    let val = ex.value.as_deref().expect("value preserved");
    assert!(!val.contains("leak-me"), "value leaked: {val}");
    assert!(ex.ty.contains("***REDACTED***"));
}

/// Raw sentry crate is a no-op with no DSN — the invariant [`init()`]
/// relies on (`is_enabled` gates on `options.dsn.is_some()`).
#[test]
fn client_disabled_when_dsn_unset() {
    let mut opts = sentry::ClientOptions::default();
    opts.dsn = None;
    let guard = sentry::init(opts);
    assert!(!guard.is_enabled(), "client with no DSN must be disabled");
}

/// `init()`'s DSN parsing, tested on a pure helper instead of mutating the
/// process-wide `SENTRY_DSN` (CodeRabbit: `set_var`/`remove_var` racy under
/// parallel test threads). Empty/whitespace/malformed → `None` (disabled).
#[test]
fn parse_dsn_rejects_empty_and_malformed() {
    assert_eq!(parse_dsn(""), None, "empty -> disabled");
    assert_eq!(parse_dsn("   "), None, "whitespace -> disabled");
    assert_eq!(parse_dsn("not-a-valid-dsn"), None, "malformed -> disabled");
}
