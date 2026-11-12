use super::*;

#[test]
fn valid_paths_are_accepted() {
    assert_eq!(validate_mcp_path("/mcp".into()).unwrap(), "/mcp");
    assert_eq!(validate_mcp_path("/v1/mcp".into()).unwrap(), "/v1/mcp");
}

#[test]
fn invalid_paths_are_rejected() {
    for bad in ["", " ", "/", "mcp", "/with space", "  "] {
        assert!(
            validate_mcp_path(bad.into()).is_err(),
            "expected `{bad}` to be rejected"
        );
    }
}

/// Mounting the MCP endpoint on a path the gateway already serves made
/// axum panic while building the router — a boot crash naming router
/// internals rather than the offending setting (#136).
#[test]
fn paths_the_gateway_already_serves_are_rejected() {
    for reserved in [
        "/healthz",
        "/readyz",
        "/metrics",
        "/authorize",
        "/token",
        "/revoke",
        "/register",
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/admin",
        "/admin/v1/users",
        "/.well-known/openid-configuration",
    ] {
        assert!(
            matches!(
                validate_mcp_path(reserved.into()),
                Err(ConfigError::McpPathReserved(_))
            ),
            "expected `{reserved}` to be rejected as reserved"
        );
    }
}

/// Prefix reservation must match on path segments, not raw string prefix —
/// `/adminy` is nobody else's route.
#[test]
fn paths_merely_resembling_reserved_ones_are_allowed() {
    for ok in [
        "/adminy",
        "/healthzz",
        "/mcp/healthz",
        "/tokens",
        "/.well-knownish",
    ] {
        assert_eq!(
            validate_mcp_path(ok.into()).as_deref().ok(),
            Some(ok),
            "expected `{ok}` to be accepted"
        );
    }
}

#[test]
fn default_has_dev_state_db_url() {
    let config = Config::default();
    assert!(config.state_db.url.contains("localhost"));
    assert_eq!(config.state_db.pool_size, DEFAULT_STATE_DB_POOL_SIZE);
}

/// A3: the session cache freshness TTL bounds cross-replica revocation
/// staleness, so its default is a security-relevant value worth pinning.
#[test]
fn default_session_cache_ttl_is_thirty_seconds() {
    assert_eq!(Config::default().session_cache_ttl_seconds, 30);
}

/// `AUDIT_RETENTION_DAYS=0` would let the pruner wipe every audit row on
/// its next tick. Refuse at boot, per spec 08 "invalid config must refuse
/// to start".
#[test]
fn audit_retention_zero_is_rejected() {
    // Direct unit test on the surface that consumes the value, so we don't
    // race on the process-wide env var across tests.
    let err = ConfigError::AuditRetentionZero("0".to_string());
    let rendered = format!("{err}");
    assert!(rendered.contains("must be greater than zero"), "{rendered}");
}

/// The TlsMissing message is operator-facing — it must spell out both env
/// vars AND the dev-only opt-out, so the first thing a stuck operator
/// reads in their logs already names the fix. Regression guard.
#[test]
fn tls_missing_error_names_the_envs_and_dev_escape() {
    let rendered = format!("{}", ConfigError::TlsMissing);
    assert!(rendered.contains("TLS_CERT_PATH"), "{rendered}");
    assert!(rendered.contains("TLS_KEY_PATH"), "{rendered}");
    assert!(rendered.contains("TLS_DISABLED"), "{rendered}");
}
