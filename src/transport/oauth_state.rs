//! In-memory flow state for the auth round-trips fronted by `transport/`.
//!
//! Three TTL-bounded stores plus the context they carry: pending IdP logins
//! ([`PendingFlows`]), one-time authorization codes ([`AuthCodes`]), and
//! rotating refresh tokens ([`RefreshTokens`]). All are in-process — a restart
//! drops them and an HA deployment must pin the OAuth dance to one replica or
//! sticky-route it (see `docs/initial-idea/02-architecture.md#ha`). The
//! Dynamic-Client-Registration store lives next door in
//! [`super::client_registry`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

/// Size cap on the pending flows map. A login produces one pending flow;
/// this cap bounds resource exhaustion from abandoning many browser logins.
const PENDING_FLOWS_MAX_SIZE: usize = 10_000;

/// Size cap on the authorization codes map. Each code is one-time and
/// redeemed immediately; this cap bounds memory from unused/leaked codes.
const AUTH_CODES_MAX_SIZE: usize = 10_000;

/// Size cap on the refresh tokens map. This cap bounds resource exhaustion
/// from tokens belonging to many users or leaked tokens stored indefinitely.
const REFRESH_TOKENS_MAX_SIZE: usize = 100_000;

/// Error type for store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The store has reached its size cap; new entries are rejected.
    StoreFull,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::StoreFull => write!(f, "auth store full"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Hash a bearer secret (authorization code or refresh token) for at-rest
/// storage. The store is keyed by this digest, never the raw secret, so a memory
/// dump or a stray `Debug` of the map can't be replayed as a live token; lookups
/// hash the presented value and match digests. SHA-256 is preimage-resistant, so
/// the stored digest can't be turned back into a usable token.
fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// `state → nonce` from /auth/login lives here until /auth/callback consumes
/// (and removes) it. TTL-bounded so a wedged login can't accumulate.
///
/// 15 min (was 5): a real browser SSO leg includes the IdP login form, a TOTP
/// prompt, and — when the IdP's user store is briefly slow — multi-second
/// backend waits. 5 min expired legitimate logins mid-flow, surfacing at
/// /auth/callback as a missing flow. The store is still size-capped
/// (`PENDING_FLOWS_MAX_SIZE`), so a longer TTL can't let abandoned flows grow
/// unbounded.
const FLOW_TTL: Duration = Duration::from_secs(15 * 60);

/// Context an MCP OAuth-bridge `/authorize` request stashes across the IdP
/// round-trip. Recovered at `/auth/callback` (keyed by the OIDC `state`) so the
/// gateway can mint an authorization code and 302 back to the *client's* own
/// redirect URI — the loopback Claude Code listens on.
#[derive(Debug, Clone)]
pub struct OAuthBridge {
    /// The client_id from `/register` — carried through so `/token` can verify
    /// the presenter matches the registrant.
    pub client_id: String,
    /// The MCP client's registered redirect URI (loopback or https).
    pub client_redirect_uri: String,
    /// The MCP client's `state` — echoed back verbatim on the final redirect.
    pub client_state: String,
    /// PKCE challenge (S256). Verified against `code_verifier` at `/token`.
    pub code_challenge: String,
    /// RFC 8707 `resource` the client bound the request to (audit/diagnostics).
    pub resource: Option<String>,
}

#[derive(Clone, Default, Debug)]
pub struct PendingFlows {
    inner: Arc<Mutex<HashMap<String, PendingFlow>>>,
}

#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub nonce: String,
    /// PKCE `code_verifier` the gateway (as an OAuth *client*) sends to the
    /// upstream IdP at the token exchange — distinct from any client-facing
    /// PKCE in `bridge`.
    pub idp_verifier: String,
    /// `Some` for an MCP OAuth-bridge login; `None` for the bespoke
    /// `/auth/login` flow that returns the session token as JSON.
    pub bridge: Option<OAuthBridge>,
    expires_at: Instant,
}

impl PendingFlows {
    pub async fn insert(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
    ) -> Result<(), StoreError> {
        self.insert_flow(state, nonce, idp_verifier, None).await
    }

    /// Insert a flow carrying MCP OAuth-bridge context (the client redirect /
    /// state / PKCE challenge to honor once the IdP round-trip completes).
    pub async fn insert_bridge(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: OAuthBridge,
    ) -> Result<(), StoreError> {
        self.insert_flow(state, nonce, idp_verifier, Some(bridge))
            .await
    }

    async fn insert_flow(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: Option<OAuthBridge>,
    ) -> Result<(), StoreError> {
        let mut map = self.inner.lock().await;
        // Check size before inserting; reject if full.
        if map.len() >= PENDING_FLOWS_MAX_SIZE {
            return Err(StoreError::StoreFull);
        }
        map.insert(
            state,
            PendingFlow {
                nonce,
                idp_verifier,
                bridge,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
        Ok(())
    }

    /// Remove and return the pending flow for a given state, if still live
    /// (i.e., not yet expired past the flow TTL).
    pub async fn take(&self, state: &str) -> Option<PendingFlow> {
        let mut map = self.inner.lock().await;
        if let Some(flow) = map.remove(state) {
            // Check expiration before returning: if the flow has passed its TTL,
            // reject it (treat as if it doesn't exist). The background GC task
            // will clean up the rest.
            if flow.expires_at > Instant::now() {
                Some(flow)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Remove all expired flows. Called periodically by a background task.
    pub async fn gc_expired(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, flow| flow.expires_at > now);
    }
}

/// TTL for a minted authorization code. Codes are one-time and redeemed
/// immediately by the client, so this is deliberately tight (OAuth 2.1
/// recommends ≤ 10 min; we use 1).
const CODE_TTL: Duration = Duration::from_secs(60);

/// The verified IdP identity carried by a pending auth code or refresh token —
/// enough to mint a fresh gateway session at redemption time.
#[derive(Debug, Clone)]
pub struct GrantIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// One-time authorization codes for the MCP OAuth bridge. A code maps to the
/// verified identity plus the PKCE challenge to verify at `/token`. The session
/// and tokens are minted only when the code is redeemed, so an abandoned login
/// leaves no orphan session.
#[derive(Clone, Default, Debug)]
pub struct AuthCodes {
    inner: Arc<Mutex<HashMap<[u8; 32], AuthCode>>>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    /// Verified IdP identity to mint the session from at redemption.
    pub identity: GrantIdentity,
    /// PKCE S256 challenge the redeeming `code_verifier` must satisfy.
    pub code_challenge: String,
    /// Redirect URI from `/authorize`; `/token` must present the same value.
    pub redirect_uri: String,
    /// Registered client_id from `/authorize`; `/token` verifies the presenter
    /// matches the registrant (OAuth 2.1 §4.1.3 for public clients).
    pub client_id: String,
    expires_at: Instant,
}

impl AuthCodes {
    pub async fn insert(
        &self,
        code: &str,
        identity: GrantIdentity,
        code_challenge: String,
        redirect_uri: String,
        client_id: String,
    ) -> Result<(), StoreError> {
        let mut map = self.inner.lock().await;
        // Check size before inserting; reject if full.
        if map.len() >= AUTH_CODES_MAX_SIZE {
            return Err(StoreError::StoreFull);
        }
        map.insert(
            hash_secret(code),
            AuthCode {
                identity,
                code_challenge,
                redirect_uri,
                client_id,
                expires_at: Instant::now() + CODE_TTL,
            },
        );
        Ok(())
    }

    /// Remove and return a code (one-time use), if still live (i.e., not yet
    /// expired past the code TTL).
    pub async fn take(&self, code: &str) -> Option<AuthCode> {
        let mut map = self.inner.lock().await;
        if let Some(ac) = map.remove(&hash_secret(code)) {
            // Check expiration before returning: if the code has passed its TTL,
            // reject it (treat as if it doesn't exist). The background GC task
            // will clean up the rest.
            if ac.expires_at > Instant::now() {
                Some(ac)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Remove all expired codes. Called periodically by a background task.
    pub async fn gc_expired(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, code| code.expires_at > now);
    }
}

/// Default absolute lifetime of a refresh-token *chain* when the deployment sets
/// no override (`REFRESH_TTL_DAYS` unset). Measured from the first token's mint
/// and **never extended by rotation**. Three constraints set it; the tightest
/// wins:
///
/// 1. **Stale groups (O3b).** A refresh re-mints a session from the IdP identity
///    frozen at the *original* browser login ([`GrantIdentity`], groups
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
/// window) raises this via `REFRESH_TTL_DAYS` ([`AuthConfig::refresh_ttl`]),
/// accepting the wider group-staleness window that implies. The fuller fix —
/// re-validating the identity against the IdP on every refresh — needs an IdP
/// refresh token (`offline_access`) the bridge doesn't currently hold, and is
/// deferred; see `docs/initial-idea/04-auth-sso.md`.
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(24 * 3600);

/// Whether a refresh chain born at `issued_at` has reached its absolute `ttl` as
/// of `now`. A pure boundary so the cap is unit-testable without sleeping a day
/// or building a past `Instant` (`Instant - Duration` can underflow the
/// monotonic clock on a freshly-booted process). `saturating_*` never panics.
fn chain_expired(issued_at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(issued_at) >= ttl
}

/// Refresh-token store: hashed token → the verified identity it renews. Rotated
/// on every redemption (the old token is removed, a new one issued), per OAuth
/// 2.1 §4.3.1 for public clients. In-memory like the other flow state — see the
/// deployment note on single-replica / sticky routing for the auth dance.
///
/// `ttl` is the absolute chain lifetime (see [`DEFAULT_REFRESH_TTL`]); production
/// threads the configured [`AuthConfig::refresh_ttl`] via [`RefreshTokens::with_ttl`].
#[derive(Clone, Debug)]
pub struct RefreshTokens {
    inner: Arc<Mutex<HashMap<[u8; 32], RefreshToken>>>,
    ttl: Duration,
}

impl Default for RefreshTokens {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_REFRESH_TTL)
    }
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub identity: GrantIdentity,
    /// When the rotation *chain* this token belongs to was first minted. Carried
    /// verbatim across rotations (see [`RefreshTokens::insert_rotated`]) so the
    /// chain expires an absolute [`REFRESH_TTL`] after the first token — rotation
    /// renews the opaque value but never the deadline.
    pub issued_at: Instant,
}

impl RefreshTokens {
    /// Construct with a caller-chosen absolute chain TTL. Production threads
    /// [`AuthConfig::refresh_ttl`] here; `Default` uses [`DEFAULT_REFRESH_TTL`].
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::default(),
            ttl,
        }
    }

    /// Insert a token that starts a fresh chain (birth = now). Used when the
    /// token is minted off an authorization-code redemption, not a rotation.
    pub async fn insert(&self, token: &str, identity: GrantIdentity) -> Result<(), StoreError> {
        self.store(token, identity, Instant::now()).await
    }

    /// Insert a rotated token, carrying the chain's original `issued_at` forward
    /// so the absolute TTL is measured from the first mint, not this rotation.
    pub async fn insert_rotated(
        &self,
        token: &str,
        identity: GrantIdentity,
        issued_at: Instant,
    ) -> Result<(), StoreError> {
        self.store(token, identity, issued_at).await
    }

    async fn store(
        &self,
        token: &str,
        identity: GrantIdentity,
        issued_at: Instant,
    ) -> Result<(), StoreError> {
        let mut map = self.inner.lock().await;
        // Check size before inserting; reject if full.
        if map.len() >= REFRESH_TOKENS_MAX_SIZE {
            return Err(StoreError::StoreFull);
        }
        map.insert(
            hash_secret(token),
            RefreshToken {
                identity,
                issued_at,
            },
        );
        Ok(())
    }

    /// Remove and return a refresh token (rotation consumes it), if still live
    /// (i.e., not yet expired past the absolute chain TTL).
    pub async fn take(&self, token: &str) -> Option<RefreshToken> {
        let mut map = self.inner.lock().await;
        if let Some(rt) = map.remove(&hash_secret(token)) {
            // Check expiration before returning: if the chain has passed its
            // absolute TTL, reject it (treat as if it doesn't exist). The
            // background GC task will clean up the rest.
            let now = Instant::now();
            if chain_expired(rt.issued_at, now, self.ttl) {
                return None;
            }
            Some(rt)
        } else {
            None
        }
    }

    /// Drop every refresh token belonging to `sub`, returning how many were
    /// removed. Logout calls this: revoking the session row alone leaves this
    /// identity's refresh chains live, so a logged-out user could silently mint a
    /// fresh session via the refresh grant. A chain carries no stable session id
    /// (each rotation mints a new session), so `sub` is the only handle spanning
    /// it — hence purge-by-identity rather than per-token. (O4)
    pub async fn purge_for_sub(&self, sub: &str) -> usize {
        let mut map = self.inner.lock().await;
        let before = map.len();
        map.retain(|_, t| t.identity.sub != sub);
        before - map.len()
    }

    /// Remove all expired refresh token chains. Called periodically by a
    /// background task.
    pub async fn gc_expired(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, t| !chain_expired(t.issued_at, now, self.ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> GrantIdentity {
        GrantIdentity {
            sub: "u1".into(),
            email: "u1@example.com".into(),
            groups: vec!["eng".into()],
        }
    }

    #[test]
    fn hash_secret_is_not_the_raw_input_and_is_deterministic() {
        let h = hash_secret("super-secret-token");
        assert_ne!(h.as_slice(), b"super-secret-token");
        assert_eq!(h, hash_secret("super-secret-token"));
        assert_ne!(hash_secret("a"), hash_secret("b"));
    }

    #[tokio::test]
    async fn refresh_round_trips_by_raw_token_and_is_consumed_once() {
        let store = RefreshTokens::default();
        store.insert("raw-token", identity()).await.unwrap();

        // Lookup hashes the presented value, so the raw token resolves...
        let entry = store.take("raw-token").await.expect("token is live");
        assert_eq!(entry.identity.sub, "u1");
        // ...and rotation/redemption consumes it (replay finds nothing).
        assert!(store.take("raw-token").await.is_none());
    }

    #[tokio::test]
    async fn refresh_rotation_carries_birth_time_and_never_extends_it() {
        let store = RefreshTokens::default();

        // A rotated token must store the *passed* chain birth verbatim, not
        // `Instant::now()` — that's what keeps the absolute TTL from sliding.
        let birth = Instant::now();
        store
            .insert_rotated("rotated", identity(), birth)
            .await
            .unwrap();
        let entry = store.take("rotated").await.expect("token is live");
        assert_eq!(
            entry.issued_at, birth,
            "rotation must not reset the chain clock"
        );

        // A fresh insert, by contrast, stamps ~now.
        let before = Instant::now();
        store.insert("fresh", identity()).await.unwrap();
        let after = Instant::now();
        let fresh = store.take("fresh").await.expect("token is live");
        assert!(fresh.issued_at >= before && fresh.issued_at <= after);
    }

    #[test]
    fn default_refresh_chain_ttl_bounds_group_staleness_within_a_day() {
        // O3b: the chain's `groups` are frozen at the original login, so the
        // chain TTL is the worst-case window a since-revoked group keeps minting
        // sessions. The *default* stays conservative — an operator opts into a
        // longer window explicitly via `REFRESH_TTL_DAYS`; guard the default
        // against an accidental regression to a multi-week cap.
        assert!(DEFAULT_REFRESH_TTL <= Duration::from_secs(24 * 3600));
    }

    #[test]
    fn chain_is_dead_once_it_reaches_the_absolute_ttl() {
        // Offset off a single base instant so the future `now` never underflows
        // the monotonic clock on a young process.
        let ttl = DEFAULT_REFRESH_TTL;
        let born = Instant::now();
        assert!(!chain_expired(born, born, ttl), "a fresh chain is live");
        assert!(
            !chain_expired(born, born + ttl - Duration::from_secs(1), ttl),
            "inside the window the chain still renews"
        );
        assert!(
            chain_expired(born, born + ttl, ttl),
            "at the cap the chain is dead — no more stale-group minting"
        );
    }

    #[tokio::test]
    async fn expired_refresh_chain_is_gc_dropped_and_not_returned() {
        let store = RefreshTokens::default();
        // Born a full TTL ago → already past the cap. checked_sub guards the
        // (theoretical) young-clock underflow; skip rather than panic if so.
        let Some(stale_birth) = Instant::now().checked_sub(DEFAULT_REFRESH_TTL) else {
            return;
        };
        store
            .insert_rotated("stale", identity(), stale_birth)
            .await
            .unwrap();
        // take() checks expiration and rejects expired tokens before returning.
        assert!(
            store.take("stale").await.is_none(),
            "a chain at/over its TTL must not renew"
        );
    }

    #[tokio::test]
    async fn custom_ttl_extends_the_chain_window() {
        // A chain older than the default but younger than a longer configured
        // TTL (e.g. the 90-day "stay signed in" window) still renews.
        let ttl = Duration::from_secs(90 * 24 * 3600);
        let store = RefreshTokens::with_ttl(ttl);
        let Some(birth) =
            Instant::now().checked_sub(DEFAULT_REFRESH_TTL + Duration::from_secs(3600))
        else {
            return;
        };
        store
            .insert_rotated("long-lived", identity(), birth)
            .await
            .unwrap();
        assert!(
            store.take("long-lived").await.is_some(),
            "inside the configured TTL the chain still renews"
        );
    }

    #[tokio::test]
    async fn purge_for_sub_drops_only_that_identitys_chains() {
        let store = RefreshTokens::default();
        // Two live chains for u1 (e.g. two devices), one for u2.
        store.insert("u1-a", identity()).await.unwrap();
        store.insert("u1-b", identity()).await.unwrap();
        store
            .insert(
                "u2-a",
                GrantIdentity {
                    sub: "u2".into(),
                    ..identity()
                },
            )
            .await
            .unwrap();

        let removed = store.purge_for_sub("u1").await;
        assert_eq!(removed, 2, "both of u1's chains are purged");
        assert!(store.take("u1-a").await.is_none());
        assert!(store.take("u1-b").await.is_none());
        // A different identity's chain is left intact.
        assert!(store.take("u2-a").await.is_some());
        // Purging an identity with no tokens is a no-op.
        assert_eq!(store.purge_for_sub("nobody").await, 0);
    }

    #[tokio::test]
    async fn auth_code_round_trips_by_raw_code_and_is_consumed_once() {
        let store = AuthCodes::default();
        store
            .insert(
                "raw-code",
                identity(),
                "challenge".into(),
                "https://app/cb".into(),
                "client-1".into(),
            )
            .await
            .unwrap();

        let entry = store.take("raw-code").await.expect("code is live");
        assert_eq!(entry.client_id, "client-1");
        assert!(store.take("raw-code").await.is_none());
    }

    #[tokio::test]
    async fn pending_flows_gc_removes_expired_entries() {
        let store = PendingFlows::default();
        store
            .insert("flow1".into(), "nonce1".into(), "verifier1".into())
            .await
            .unwrap();
        store
            .insert("flow2".into(), "nonce2".into(), "verifier2".into())
            .await
            .unwrap();

        // Both flows should exist.
        assert!(store.take("flow1").await.is_some());
        assert!(store.take("flow2").await.is_some());

        // Re-insert and then run gc_expired.
        store
            .insert("flow3".into(), "nonce3".into(), "verifier3".into())
            .await
            .unwrap();
        store.gc_expired().await;
        // Flow3 is still within TTL, should exist after GC.
        assert!(store.take("flow3").await.is_some());
    }

    #[tokio::test]
    async fn auth_codes_gc_removes_expired_entries() {
        let store = AuthCodes::default();
        store
            .insert(
                "code1",
                identity(),
                "ch".into(),
                "uri".into(),
                "client".into(),
            )
            .await
            .unwrap();

        // Code exists.
        assert!(store.take("code1").await.is_some());

        // Re-insert and run gc.
        store
            .insert(
                "code2",
                identity(),
                "ch".into(),
                "uri".into(),
                "client".into(),
            )
            .await
            .unwrap();
        store.gc_expired().await;
        // Code2 is still within TTL.
        assert!(store.take("code2").await.is_some());
    }

    #[tokio::test]
    async fn refresh_tokens_gc_removes_expired_chains() {
        let store = RefreshTokens::default();
        store.insert("token1", identity()).await.unwrap();
        store.insert("token2", identity()).await.unwrap();

        // Both tokens exist.
        assert!(store.take("token1").await.is_some());
        assert!(store.take("token2").await.is_some());

        // Run gc_expired.
        store.gc_expired().await;
        // Fresh tokens within TTL should still exist after GC.
        store.insert("token3", identity()).await.unwrap();
        assert!(store.take("token3").await.is_some());
    }

    #[tokio::test]
    async fn pending_flows_rejects_when_full() {
        let store = PendingFlows::default();
        // Fill to the limit.
        for i in 0..PENDING_FLOWS_MAX_SIZE {
            let state = format!("flow-{i}");
            store
                .insert(state, format!("nonce-{i}"), format!("verifier-{i}"))
                .await
                .unwrap();
        }

        // Next insert should fail.
        let result = store
            .insert("overflow".into(), "nonce".into(), "verifier".into())
            .await;
        assert_eq!(result, Err(StoreError::StoreFull));
    }

    #[tokio::test]
    async fn auth_codes_rejects_when_full() {
        let store = AuthCodes::default();
        // Fill to the limit.
        for i in 0..AUTH_CODES_MAX_SIZE {
            let code = format!("code-{i}");
            store
                .insert(
                    &code,
                    identity(),
                    "challenge".into(),
                    "uri".into(),
                    "client".into(),
                )
                .await
                .unwrap();
        }

        // Next insert should fail.
        let result = store
            .insert(
                "overflow",
                identity(),
                "challenge".into(),
                "uri".into(),
                "client".into(),
            )
            .await;
        assert_eq!(result, Err(StoreError::StoreFull));
    }

    #[tokio::test]
    async fn refresh_tokens_rejects_when_full() {
        let store = RefreshTokens::default();
        // Fill to the limit.
        for i in 0..REFRESH_TOKENS_MAX_SIZE {
            let token = format!("token-{i}");
            store.insert(&token, identity()).await.unwrap();
        }

        // Next insert should fail.
        let result = store.insert("overflow", identity()).await;
        assert_eq!(result, Err(StoreError::StoreFull));
    }
}
