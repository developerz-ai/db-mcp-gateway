//! One parser per env-driven knob of [`super::Config`], each refusing with
//! the [`ConfigError`] boot reports.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;

use super::{ConfigError, TlsConfig, bool_flag_from_env};

const MAX_PERMISSIONS_CACHE_TTL_SECONDS: u64 = 300;

pub(super) fn parse_bind(value: String) -> Result<SocketAddr, ConfigError> {
    value
        .parse()
        .map_err(|source| ConfigError::Bind { value, source })
}

pub(super) fn parse_metrics_bind(value: String) -> Result<SocketAddr, ConfigError> {
    value
        .parse()
        .map_err(|source| ConfigError::MetricsBind { value, source })
}

/// Zero would make the pruner immediately delete every audit row — a silent
/// durability violation.
pub(super) fn parse_audit_retention(value: String) -> Result<u32, ConfigError> {
    let days: u32 = value
        .parse()
        .map_err(|source| ConfigError::AuditRetentionDays {
            value: value.clone(),
            source,
        })?;
    if days == 0 {
        return Err(ConfigError::AuditRetentionZero(value));
    }
    Ok(days)
}

/// The grant cache bounds how long a revoked grant can still be honoured on a
/// replica that missed the invalidation; past five minutes that window is an
/// outage of revocation, so a larger value fails boot rather than being
/// silently clamped.
pub(super) fn parse_cache_ttl(value: String) -> Result<u64, ConfigError> {
    let ttl: u64 = value
        .parse()
        .map_err(|source| ConfigError::PermissionsCacheTtl {
            value: value.clone(),
            source,
        })?;
    if ttl > MAX_PERMISSIONS_CACHE_TTL_SECONDS {
        return Err(ConfigError::PermissionsCacheTtlTooLong(ttl));
    }
    Ok(ttl)
}

/// A concurrency ceiling: a positive integer. Zero would shed every request.
pub(super) fn parse_cap(name: &'static str, value: String) -> Result<usize, ConfigError> {
    match value.trim().parse::<usize>() {
        Ok(0) | Err(_) => Err(ConfigError::ConcurrencyCap { name, value }),
        Ok(cap) => Ok(cap),
    }
}

/// `STATE_DB_POOL_SIZE`: non-zero, and no larger than the request ceiling —
/// connections past `max_concurrent_requests` can never be checked out at
/// once, they only hold server slots.
pub(super) fn parse_pool_size(
    value: String,
    max_concurrent_requests: usize,
) -> Result<NonZeroU32, ConfigError> {
    let parsed: u32 = value
        .parse()
        .map_err(|source| ConfigError::StateDbPoolSize {
            value: value.clone(),
            source,
        })?;
    let Some(size) = NonZeroU32::new(parsed) else {
        return Err(ConfigError::StateDbPoolSizeZero);
    };
    if usize::try_from(parsed).is_ok_and(|n| n > max_concurrent_requests) {
        return Err(ConfigError::StateDbPoolSizeAboveConcurrency {
            size: parsed,
            max_concurrent_requests,
        });
    }
    Ok(size)
}

/// Resolve `TlsConfig` from `TLS_DISABLED` / `TLS_CERT_PATH` / `TLS_KEY_PATH`.
///
/// Refuses to boot without TLS unless `TLS_DISABLED=true` is set explicitly —
/// missing/empty cert paths are *not* an implicit opt-out (issue #12). The
/// readability check here is cheap and catches the common "sealed-secret
/// volume isn't mounted" failure before transport spins up.
pub(super) fn tls_from_env() -> Result<TlsConfig, ConfigError> {
    if bool_flag_from_env("TLS_DISABLED")? == Some(true) {
        return Ok(TlsConfig::Disabled);
    }

    let cert = std::env::var("TLS_CERT_PATH").ok().map(PathBuf::from);
    let key = std::env::var("TLS_KEY_PATH").ok().map(PathBuf::from);
    let (cert_path, key_path) = match (cert, key) {
        (Some(c), Some(k)) => (c, k),
        _ => return Err(ConfigError::TlsMissing),
    };

    std::fs::metadata(&cert_path).map_err(|source| ConfigError::TlsCertUnreadable {
        path: cert_path.clone(),
        source,
    })?;
    std::fs::metadata(&key_path).map_err(|source| ConfigError::TlsKeyUnreadable {
        path: key_path.clone(),
        source,
    })?;

    Ok(TlsConfig::Enabled {
        cert_path,
        key_path,
    })
}
