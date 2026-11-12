use super::*;
use crate::auth::AuthError;
use crate::config::Password;

fn account(name: &str, group: &str, token: &str) -> ServiceAccount {
    ServiceAccount {
        name: name.to_string(),
        group: group.to_string(),
        token: Password::Literal(SecretString::from(token)),
        max_concurrent_requests: None,
        require_upstream: false,
    }
}

fn good_token(suffix: &str) -> String {
    // Prefix + exactly TOKEN_BODY_CHARS lowercase hex, differentiated by
    // the suffix so each test token is distinct. Pads with `0` and
    // truncates if the suffix is the wrong width — the suffix is always
    // short hex in practice, so this just keeps the helper call sites
    // readable.
    let mut body = String::with_capacity(TOKEN_BODY_CHARS);
    body.push_str(&"0".repeat(TOKEN_BODY_CHARS));
    let s = suffix.as_bytes();
    let start = body.len() - s.len();
    body.replace_range(start.., std::str::from_utf8(s).unwrap());
    format!("{TOKEN_PREFIX}{body}")
}

#[test]
fn authenticates_a_configured_token() {
    let store = ServiceTokenStore::from_config(&[
        account("ci-bot", "svc-ci", &good_token("a")),
        account("nightly", "svc-nightly", &good_token("b")),
    ])
    .expect("valid accounts build a store");

    let identity = store
        .authenticate(&good_token("a"))
        .expect("exact token match authenticates");
    assert_eq!(identity.user_sub, "service:ci-bot");
    assert_eq!(identity.user_email, "ci-bot@service-accounts.invalid");
    assert_eq!(identity.groups, vec!["svc-ci".to_string()]);
}

#[test]
fn unknown_or_near_miss_tokens_do_not_match() {
    let store = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &good_token("a"))])
        .expect("valid account builds a store");

    // `None` here means "fall through to the JWT path", not acceptance.
    assert!(store.authenticate(&good_token("b")).is_none());
    // One byte flipped at the tail.
    let mut near = good_token("a");
    near.replace_range(near.len() - 1.., "z");
    assert!(store.authenticate(&near).is_none());
    // Truncated / extended / empty.
    let short = &good_token("a")[..TOKEN_PREFIX.len() + TOKEN_BODY_CHARS - 1];
    assert!(store.authenticate(short).is_none());
    assert!(
        store
            .authenticate(&format!("{}x", good_token("a")))
            .is_none()
    );
    assert!(store.authenticate("").is_none());
}

#[test]
fn empty_store_matches_nothing() {
    let store = ServiceTokenStore::default();
    assert!(store.authenticate(&good_token("a")).is_none());
}

#[test]
fn prefixless_token_is_rejected_at_boot() {
    let err = ServiceTokenStore::from_config(&[account(
        "ci-bot",
        "svc-ci",
        "0123456789abcdef0123456789abcdef",
    )])
    .expect_err("missing prefix must fail the build");
    assert!(matches!(&err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
    // The operator-facing message names the mint verb — and no token bytes.
    let rendered = format!("{err}");
    assert!(rendered.contains("bin/mint-service-token"), "{rendered}");
    assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
}

#[test]
fn short_token_is_rejected_at_boot() {
    let weak = format!("{TOKEN_PREFIX}tooshort");
    let err = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &weak)])
        .expect_err("short token must fail the build");
    assert!(matches!(err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
}

/// 32-character hex body — the old minimum — must now be rejected so
/// only the exact 64-hex shape can boot a store.
#[test]
fn thirty_two_char_body_is_rejected_at_boot() {
    let body = "0".repeat(32);
    let weak = format!("{TOKEN_PREFIX}{body}");
    let err = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &weak)])
        .expect_err("32-char body must fail the build");
    assert!(matches!(err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
}

/// Overlong body — even if every byte is hex — must be rejected so a
/// paste-of-junk-from-an-issue can't reach the compare loop.
#[test]
fn overlong_body_is_rejected_at_boot() {
    let body = "a".repeat(TOKEN_BODY_CHARS + 8);
    let weak = format!("{TOKEN_PREFIX}{body}");
    let err = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &weak)])
        .expect_err("overlong body must fail the build");
    assert!(matches!(err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
}

/// A 64-char body that includes a non-hex byte must be rejected —
/// `is_ascii_hexdigit` is the body-shape rule. Pinned with a body
/// length that matches `TOKEN_BODY_CHARS` so the test isolates the
/// hex rule from the length rule.
#[test]
fn non_hex_body_is_rejected_at_boot() {
    let mut body = "a".repeat(TOKEN_BODY_CHARS - 1);
    body.push('z'); // `z` is not an ASCII hex digit.
    let weak = format!("{TOKEN_PREFIX}{body}");
    let err = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &weak)])
        .expect_err("non-hex body must fail the build");
    assert!(matches!(err, ServiceTokenError::WeakToken(name) if name == "ci-bot"));
}

#[test]
fn duplicate_token_value_is_rejected_at_boot() {
    let err = ServiceTokenStore::from_config(&[
        account("ci-bot", "svc-ci", &good_token("a")),
        account("ci-bot-2", "svc-ci", &good_token("a")),
    ])
    .expect_err("a shared token value breaks audit attribution");
    assert!(
        matches!(&err, ServiceTokenError::DuplicateToken(first, second)
            if first == "ci-bot" && second == "ci-bot-2")
    );
    // Names only, never the value.
    let rendered = format!("{err}");
    assert!(!rendered.contains(&good_token("a")), "{rendered}");
}

#[test]
fn unresolved_reference_is_a_boot_error_without_material() {
    let missing = format!("DB_MCP_SVC_TEST_{}", uuid::Uuid::new_v4().simple());
    let accounts = [ServiceAccount {
        name: "ci-bot".to_string(),
        group: "svc-ci".to_string(),
        token: Password::EnvVar(missing.clone()),
        max_concurrent_requests: None,
        require_upstream: false,
    }];
    let err =
        ServiceTokenStore::from_config(&accounts).expect_err("unset env ref must fail the build");
    match err {
        ServiceTokenError::Resolve(name, SecretError::EnvNotSet(var)) => {
            assert_eq!(name, "ci-bot");
            assert_eq!(var, missing);
        }
        other => panic!("expected Resolve(EnvNotSet), got {other:?}"),
    }
}

/// Defends the no-creds-in-Debug rule: the store and its entries must
/// never render token material.
#[test]
fn debug_never_prints_token_material() {
    let store = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &good_token("c"))])
        .expect("valid account builds a store");
    let rendered = format!("{store:?}");
    assert!(rendered.contains("ci-bot"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(!rendered.contains(&good_token("c")), "{rendered}");
    assert!(!rendered.contains(TOKEN_PREFIX), "{rendered}");
}

/// The middleware logs `identity.session_id` on every request; pin the
/// redaction contract of the identity itself (email is PII-shaped even
/// when synthesized).
#[test]
fn service_identity_debug_redacts_email() {
    let store = ServiceTokenStore::from_config(&[account("ci-bot", "svc-ci", &good_token("d"))])
        .expect("valid account builds a store");
    let identity = store.authenticate(&good_token("d")).expect("match");
    let rendered = format!("{identity:?}");
    assert!(rendered.contains("service:ci-bot"), "{rendered}");
    assert!(!rendered.contains("service-accounts.invalid"), "{rendered}");
}

/// Belt-and-suspenders for `AuthError`: if a future refactor maps a
/// service-token failure onto an auth error, that error must still carry
/// no token material. Pins the enum's existing discipline as it applies
/// to this feature.
#[test]
fn auth_errors_carry_no_token_material() {
    let token = good_token("e");
    for err in [AuthError::MissingBearer, AuthError::InvalidSession] {
        assert!(!format!("{err}").contains(&token));
    }
}

/// The account's policy rides with the identity it authenticates; the
/// identity itself is unchanged (audit subject `service:<name>`).
#[test]
fn authenticate_caller_carries_the_account_policy() {
    let mut fleet = account("fleet", "svc-agents", &good_token("f"));
    fleet.max_concurrent_requests = Some(64);
    fleet.require_upstream = true;
    let store = ServiceTokenStore::from_config(&[fleet]).expect("valid account builds a store");
    let (identity, policy) = store.authenticate_caller(&good_token("f")).expect("match");
    assert_eq!(identity.user_sub, "service:fleet");
    assert_eq!(identity.groups, vec!["svc-agents".to_string()]);
    assert_eq!(
        policy,
        ServicePolicy {
            require_upstream: true,
            max_concurrent_requests: Some(64),
        }
    );
}
