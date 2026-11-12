//! One row per credential form `scrub_str` must catch (plan 101 slice 11
//! step 1), and one per benign form it must leave alone.

use super::scrubber;

const SVC: &str = "dbmcp_svc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlLXZhbHVl";

/// `(input, secret substring that must not survive)`.
fn leaking_forms() -> Vec<(String, &'static str)> {
    vec![
        (format!("token rejected: {SVC}"), &SVC[10..]),
        (format!("token rejected: {}", &SVC[..30]), &SVC[10..30]),
        ("Authorization: Bearer abc.def-ghi".into(), "abc.def-ghi"),
        ("sent bearer s3cr3t-opaque to idp".into(), "s3cr3t-opaque"),
        ("authorization=Basic dXNlcjpwYXNz".into(), "dXNlcjpwYXNz"),
        (format!("id_token {JWT} expired"), "c2lnbmF0dXJlLXZhbHVl"),
        (format!("jwt={JWT}"), "eyJzdWIiOiJ1c2VyIn0"),
        ("postgres://:onlypass@db/app".into(), "onlypass"),
        ("postgres://app:pa/ss@db/app".into(), "pa/ss"),
        ("postgres://app:p@ss@db.internal/app".into(), "p@ss"),
        ("mongodb://app:x@y@mongo:27017/db".into(), "x@y"),
        (
            "https://ghp_tokenvalue@github.com/org/repo".into(),
            "ghp_tokenvalue",
        ),
        (r#"{"password":"hunter2"}"#.into(), "hunter2"),
        (r#"{"client_secret": "sh-h"}"#.into(), "sh-h"),
        (r#"{"password":"esc\"aped"}"#.into(), "aped"),
        ("password=\"correct horse battery\"".into(), "horse battery"),
        ("secret: 'two words'".into(), "two words"),
        ("api_key=ak-123".into(), "ak-123"),
        ("apikey: ak-456".into(), "ak-456"),
        ("x-api-key=ak-789".into(), "ak-789"),
        ("cookie=sid-abc".into(), "sid-abc"),
        ("credential=cr-1".into(), "cr-1"),
        ("credentials: cr-2".into(), "cr-2"),
        ("private_key=pk-1".into(), "pk-1"),
        ("privateKey: pk-2".into(), "pk-2"),
        ("PASSWORD=Hunter2".into(), "Hunter2"),
        (
            "SESSION_SIGNING_KEY=jwt-hs256-base64-secret".into(),
            "jwt-hs256-base64-secret",
        ),
        (
            "STATE_DB_URL=postgres://db.internal/app".into(),
            "db.internal",
        ),
        (
            "state_db_url: postgres://app:s3cr3t@db.internal/app".into(),
            "s3cr3t",
        ),
        ("OIDC_CLIENT_SECRET: s3cr3t-value".into(), "s3cr3t-value"),
    ]
}

#[test]
fn no_secret_substring_survives_any_form() {
    let scrubber = scrubber();
    for (input, secret) in leaking_forms() {
        let out = scrubber.scrub_str(&input);
        assert!(
            !out.contains(secret),
            "{input:?} leaked {secret:?}: {out:?}"
        );
        assert!(out.contains("***REDACTED***"), "{input:?} -> {out:?}");
    }
}

#[test]
fn every_db_scheme_loses_userinfo_and_keeps_host() {
    let scrubber = scrubber();
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
        assert!(out.contains("://***REDACTED***@"), "{raw} -> {out}");
        assert!(!out.contains(":p@"), "userinfo leaked: {raw} -> {out}");
    }
}

#[test]
fn benign_text_is_byte_identical() {
    let scrubber = scrubber();
    for raw in [
        "query returned 42 rows from table users in 3ms",
        "see https://example.com/docs for details",
        "https://example.com/a?redirect=/b#frag",
        "state DB: failed to connect (pool_timed_out; DSN withheld)",
        "token_endpoint https://idp/token",
        "tokens used: 12",
        "MY_STATE_DB_URL=harmless",
        "expected a dbmcp_svc_ prefix",
        "user alice@example.com denied",
    ] {
        assert_eq!(scrubber.scrub_str(raw), raw, "benign text rewritten");
    }
}

#[test]
fn benign_sibling_survives_a_redacted_key() {
    let out = scrubber().scrub_str("state_db_url: postgres://db.internal/app ok=1");
    assert!(out.contains("ok=1"), "benign sibling key clobbered: {out}");
    assert!(!out.contains("db.internal"), "{out}");
}
