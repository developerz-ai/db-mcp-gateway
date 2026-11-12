//! Absolute lifetime of a refresh-token rotation chain.

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};

/// Default absolute lifetime of a refresh-token *chain* when the deployment sets
/// no override (`REFRESH_TTL_DAYS` unset). Measured from the first token's mint
/// and **never extended by rotation**. Three constraints set it; the tightest
/// wins:
///
/// 1. **Stale groups (O3b).** A refresh re-mints a session from the IdP identity
///    frozen at the *original* browser login ([`super::GrantIdentity`], groups
///    included), so a group change at the IdP (off-boarding, role downgrade)
///    can't reach the gateway while the chain lives. This cap is that staleness
///    window: once it elapses, silent refresh stops and a fresh `/authorize`
///    login re-reads `groups`. Keep it below the org's group-review /
///    deprovisioning cadence.
/// 2. Bounds a leaked (and silently rotated) chain's usefulness.
/// 3. Without any cap, a continuously rotated chain would live forever.
///
/// One day is a conservative default: it spans a working day of silent renewals,
/// yet a revoked group reaches the gateway within an operational window. An
/// operator who wants longer-lived sessions (e.g. a 90-day "stay signed in"
/// window) raises this via `REFRESH_TTL_DAYS` ([`crate::auth::AuthConfig::refresh_ttl`]),
/// accepting the wider group-staleness window that implies. The fuller fix —
/// re-validating the identity against the IdP on every refresh — needs an IdP
/// refresh token (`offline_access`) the bridge doesn't currently hold, and is
/// deferred; see `website/docs/initial-idea/04-auth-sso.md`.
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(24 * 3600);

/// Whether a refresh chain born at `issued_at` has reached its absolute `ttl` as
/// of `now`. A pure boundary so the cap is unit-testable without sleeping a day.
/// Wall-clock (not `Instant`) because the chain outlives the process: the birth
/// time round-trips through `oauth_refresh_tokens.chain_issued_at`, and a
/// monotonic clock means nothing across a restart.
pub(super) fn chain_expired(issued_at: DateTime<Utc>, now: DateTime<Utc>, ttl: Duration) -> bool {
    let elapsed = now.signed_duration_since(issued_at);
    elapsed >= ChronoDuration::from_std(ttl).unwrap_or(ChronoDuration::MAX)
}
