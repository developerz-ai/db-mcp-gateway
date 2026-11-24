//! `SESSION_CACHE_TTL_SECONDS`: bounded, because it is the cross-replica
//! window in which a revoked session is still honoured.

use super::ConfigError;

/// Past this a revoke-sessions call is effectively an outage of revocation on
/// every replica but the one that served it. Same ceiling as the grant cache.
pub(super) const MAX_SESSION_CACHE_TTL_SECONDS: u64 = 300;

/// `0` is valid (re-validate every request). Above the ceiling clamps with a
/// `WARN` rather than failing boot: the variable shipped unbounded, so an
/// existing large value must keep booting — just no longer stretch the window.
pub(super) fn parse_session_cache_ttl(value: &str) -> Result<u64, ConfigError> {
    let ttl: u64 = value
        .trim()
        .parse()
        .map_err(|source| ConfigError::SessionCacheTtl {
            value: value.to_string(),
            source,
        })?;
    if ttl > MAX_SESSION_CACHE_TTL_SECONDS {
        tracing::warn!(
            requested = ttl,
            clamped_to = MAX_SESSION_CACHE_TTL_SECONDS,
            "SESSION_CACHE_TTL_SECONDS above the maximum; clamped"
        );
        return Ok(MAX_SESSION_CACHE_TTL_SECONDS);
    }
    Ok(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cache_ttl_clamps_to_five_minutes() {
        assert_eq!(parse_session_cache_ttl("0").ok(), Some(0));
        assert_eq!(parse_session_cache_ttl("300").ok(), Some(300));
        assert_eq!(parse_session_cache_ttl("301").ok(), Some(300));
        assert_eq!(parse_session_cache_ttl("86400").ok(), Some(300));
        assert!(matches!(
            parse_session_cache_ttl("soon"),
            Err(ConfigError::SessionCacheTtl { .. })
        ));
    }
}
