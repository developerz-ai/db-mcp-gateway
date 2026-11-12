use super::*;

#[test]
fn default_uses_groups_and_eight_hour_ttl() {
    let config = AuthConfig::default();
    assert_eq!(config.groups_claim, "groups");
    assert_eq!(config.session_ttl, Duration::from_secs(8 * 3600));
    assert_eq!(config.refresh_ttl, Duration::from_secs(24 * 3600));
    assert!(!config.allow_insecure_signing_key);
}

#[test]
fn default_signing_key_rejected() {
    let config = AuthConfig::default();
    assert!(matches!(
        check_signing_key(&config),
        Err(AuthConfigError::DefaultSigningKey)
    ));
}

#[test]
fn default_signing_key_allowed_when_waived_for_loopback_issuer() {
    let config = AuthConfig {
        issuer: "http://127.0.0.1:9000".into(),
        allow_insecure_signing_key: true,
        ..AuthConfig::default()
    };
    assert!(check_signing_key(&config).is_ok());
}

#[test]
fn custom_signing_key_allowed() {
    // 32 bytes: the shortest key a non-mock gateway accepts.
    let config = AuthConfig {
        session_signing_key: b"a-unique-production-signing-key!".to_vec(),
        ..AuthConfig::default()
    };
    assert_eq!(config.session_signing_key.len(), MIN_SIGNING_KEY_BYTES);
    assert!(check_signing_key(&config).is_ok());
}

/// `SESSION_SIGNING_KEY=` (e.g. `${SIGNING_KEY}` unset in compose/Helm)
/// must not boot: an empty HMAC key signs every session JWT.
#[test]
fn empty_signing_key_rejected() {
    let config = AuthConfig {
        session_signing_key: Vec::new(),
        ..AuthConfig::default()
    };
    assert!(matches!(
        check_signing_key(&config),
        Err(AuthConfigError::DefaultSigningKey)
    ));
}

#[test]
fn short_signing_key_rejected() {
    let config = AuthConfig {
        session_signing_key: vec![b'k'; MIN_SIGNING_KEY_BYTES - 1],
        ..AuthConfig::default()
    };
    assert!(matches!(
        check_signing_key(&config),
        Err(AuthConfigError::DefaultSigningKey)
    ));
}

/// The waiver is the documented escape hatch for local dev; short and
/// empty keys stay legal there.
#[test]
fn short_and_empty_signing_keys_allowed_when_waived() {
    for key in [Vec::new(), b"short".to_vec()] {
        let config = AuthConfig {
            issuer: "http://localhost:9000".into(),
            session_signing_key: key,
            allow_insecure_signing_key: true,
            ..AuthConfig::default()
        };
        assert!(check_signing_key(&config).is_ok());
    }
}

/// The rejection message must never carry key material — it lands in logs.
#[test]
fn rejection_message_carries_no_key_material() {
    let message = AuthConfigError::DefaultSigningKey.to_string();
    assert!(!message.contains(DEFAULT_DEV_SIGNING_KEY), "{message}");
}

#[test]
fn insecure_key_waiver_refused_with_remote_issuer() {
    for issuer in ["https://idp.example.com", "http://idp.example.com", ""] {
        let config = AuthConfig {
            issuer: issuer.into(),
            allow_insecure_signing_key: true,
            ..AuthConfig::default()
        };
        assert!(
            matches!(
                check_signing_key(&config),
                Err(AuthConfigError::InsecureKeyWithRemoteIssuer)
            ),
            "{issuer}"
        );
    }
}

#[test]
fn ttl_parses_whole_units_in_bounds() {
    assert_eq!(
        parse_ttl("SESSION_TTL_HOURS", "8", 3600, SESSION_TTL_HOURS_MAX).unwrap(),
        Duration::from_secs(8 * 3600)
    );
    assert_eq!(
        parse_ttl("REFRESH_TTL_DAYS", "90", 86_400, REFRESH_TTL_DAYS_MAX).unwrap(),
        Duration::from_secs(90 * 86_400)
    );
}

#[test]
fn ttl_rejects_zero_over_max_overflow_and_garbage() {
    for value in ["0", "169", "18446744073709551615", "-1", "8h", ""] {
        assert!(
            matches!(
                parse_ttl("SESSION_TTL_HOURS", value, 3600, SESSION_TTL_HOURS_MAX),
                Err(AuthConfigError::Ttl { .. })
            ),
            "{value:?}"
        );
    }
}
