//! Process-wide state shared with every request handler.
//!
//! Cloned per request — internals are `Arc`-shared so cloning is cheap. Kept in
//! `transport/` because everything here is HTTP-layer plumbing; the auth
//! primitives themselves live under `crate::auth`.
//!
//! `auth = None` is the test bootstrap (no IdP, no state DB needed). The
//! production binary always sets `Some(AuthFacade)`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use super::probes::ShutdownFlag;
use crate::auth::{AuthConfig, OidcClient, SessionStore};
use crate::authz::PermissionsCache;
use crate::config::ConfigFile;
use crate::exec::AdapterRegistry;
use crate::state::permissions::PermissionsRepo;

/// `state → nonce` from /auth/login lives here until /auth/callback consumes
/// (and removes) it. TTL-bounded so a wedged login can't accumulate.
const FLOW_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug)]
pub struct AppState {
    pub auth: Option<AuthFacade>,
    /// Loaded `servers:` + `permissions:` from the YAML config. Empty when
    /// tests don't care about tool dispatch.
    pub config: Arc<ConfigFile>,
    /// Per-`(server, database)` `DbAdapter` registry. Lazy; opens the
    /// backend-specific adapter (today only `PgAdapter`) on first use.
    pub adapter_registry: AdapterRegistry,
    /// Gateway's own state DB. Tools that audit (`run_query`) need it; tests
    /// that only exercise the wire protocol leave it `None`.
    pub state_db: Option<PgPool>,
    /// Flipped by the graceful-shutdown handler so `/healthz` and `/readyz`
    /// return 503 while in-flight requests drain.
    pub shutdown: ShutdownFlag,
    /// Prometheus recorder handle. `None` in tests — installing the recorder
    /// is a process-wide singleton and would clash across test binaries.
    pub metrics: Option<PrometheusHandle>,
    /// Per-user DB-grant cache (#49). `None` in tests that don't exercise the
    /// resolver — dispatch falls through to YAML-only authz, which is the
    /// same path the gateway took before #49.
    pub permissions_cache: Option<PermissionsCache>,
    /// Permissions store handle. `Some` whenever the admin API (#52) is
    /// mounted; the admin handlers read/write through this. The cache uses
    /// its own clone so cache-only paths don't need the repo in `AppState`.
    /// `None` in tests that don't exercise the admin surface.
    pub permissions_repo: Option<Arc<dyn PermissionsRepo>>,
    /// The path the MCP endpoint is mounted at (e.g. `/mcp`), copied from the
    /// runtime `Config`. The OAuth metadata handlers need it to advertise the
    /// canonical resource URI (`<base><mcp_path>`) per RFC 8707.
    pub mcp_path: Arc<str>,
    /// Dynamic-Client-Registration registry: `client_id` → registered redirect
    /// URIs. `/authorize` matches the requested `redirect_uri` against this set
    /// exactly (OAuth 2.1 redirect allowlist). Always present and independent of
    /// `auth`, so `/register` persists even on the auth-less test bootstrap.
    pub client_registry: ClientRegistry,
}

impl AppState {
    /// Test helper: empty config, no auth, no state DB, empty pool registry.
    /// Production code never uses this.
    #[cfg(any(test, debug_assertions))]
    pub fn for_tests() -> Self {
        Self {
            auth: None,
            config: Arc::new(ConfigFile {
                servers: Vec::new(),
                permissions: Vec::new(),
                admin: None,
                permissions_store: None,
            }),
            adapter_registry: AdapterRegistry::new(),
            state_db: None,
            shutdown: ShutdownFlag::new(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
            mcp_path: Arc::from("/mcp"),
            client_registry: ClientRegistry::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthFacade {
    pub config: Arc<AuthConfig>,
    pub sessions: SessionStore,
    pub oidc: OidcClient,
    pub flows: PendingFlows,
    /// One-time authorization codes minted by the MCP OAuth bridge
    /// (`/authorize` → IdP → `/auth/callback` → here), redeemed at `/token`.
    /// Unused by the bespoke `/auth/login` JSON flow.
    pub codes: AuthCodes,
    /// Long-lived refresh tokens minted alongside each bridge access token, so
    /// MCP clients can silently renew an expired session without a fresh
    /// browser login. Rotated on every use (OAuth 2.1 public-client rule).
    pub refresh: RefreshTokens,
}

/// Context an MCP OAuth-bridge `/authorize` request stashes across the IdP
/// round-trip. Recovered at `/auth/callback` (keyed by the OIDC `state`) so the
/// gateway can mint an authorization code and 302 back to the *client's* own
/// redirect URI — the loopback Claude Code listens on.
#[derive(Debug, Clone)]
pub struct OAuthBridge {
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
    pub async fn insert(&self, state: String, nonce: String, idp_verifier: String) {
        self.insert_flow(state, nonce, idp_verifier, None).await;
    }

    /// Insert a flow carrying MCP OAuth-bridge context (the client redirect /
    /// state / PKCE challenge to honor once the IdP round-trip completes).
    pub async fn insert_bridge(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: OAuthBridge,
    ) {
        self.insert_flow(state, nonce, idp_verifier, Some(bridge))
            .await;
    }

    async fn insert_flow(
        &self,
        state: String,
        nonce: String,
        idp_verifier: String,
        bridge: Option<OAuthBridge>,
    ) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            state,
            PendingFlow {
                nonce,
                idp_verifier,
                bridge,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
    }

    /// Remove and return the pending flow for a given state, if still live.
    pub async fn take(&self, state: &str) -> Option<PendingFlow> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(state)
    }

    fn gc(map: &mut HashMap<String, PendingFlow>) {
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
    inner: Arc<Mutex<HashMap<String, AuthCode>>>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    /// Verified IdP identity to mint the session from at redemption.
    pub identity: GrantIdentity,
    /// PKCE S256 challenge the redeeming `code_verifier` must satisfy.
    pub code_challenge: String,
    /// Redirect URI from `/authorize`; `/token` must present the same value.
    pub redirect_uri: String,
    expires_at: Instant,
}

impl AuthCodes {
    pub async fn insert(
        &self,
        code: String,
        identity: GrantIdentity,
        code_challenge: String,
        redirect_uri: String,
    ) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            code,
            AuthCode {
                identity,
                code_challenge,
                redirect_uri,
                expires_at: Instant::now() + CODE_TTL,
            },
        );
    }

    /// Remove and return a code (one-time use), if still live.
    pub async fn take(&self, code: &str) -> Option<AuthCode> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(code)
    }

    fn gc(map: &mut HashMap<String, AuthCode>) {
        let now = Instant::now();
        map.retain(|_, code| code.expires_at > now);
    }
}

/// Lifetime of a refresh token. Long enough that a developer rarely re-does the
/// browser login, short enough to bound a leaked token's usefulness.
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Refresh-token store: token → the verified identity it renews. Rotated on
/// every redemption (the old token is removed, a new one issued), per OAuth 2.1
/// §4.3.1 for public clients. In-memory like the other flow state — see the
/// deployment note on single-replica / sticky routing for the auth dance.
#[derive(Clone, Default, Debug)]
pub struct RefreshTokens {
    inner: Arc<Mutex<HashMap<String, RefreshToken>>>,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub identity: GrantIdentity,
    expires_at: Instant,
}

impl RefreshTokens {
    pub async fn insert(&self, token: String, identity: GrantIdentity) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            token,
            RefreshToken {
                identity,
                expires_at: Instant::now() + REFRESH_TTL,
            },
        );
    }

    /// Remove and return a refresh token (rotation consumes it), if still live.
    pub async fn take(&self, token: &str) -> Option<RefreshToken> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(token)
    }

    fn gc(map: &mut HashMap<String, RefreshToken>) {
        let now = Instant::now();
        map.retain(|_, t| t.expires_at > now);
    }
}

/// TTL for a Dynamic-Client-Registration entry. A client registers, then walks
/// `/authorize` → `/token` right away and only re-authorizes on a full browser
/// re-login (refresh covers the common renewal), so the entry need only outlive
/// that. In-memory like every other flow store here (see the single-replica
/// deployment note); a restart drops it and a spec-compliant client simply
/// re-registers on the next `invalid_client`.
const CLIENT_TTL: Duration = Duration::from_secs(24 * 3600);

/// Hard cap on registered clients. `/register` is unauthenticated (open DCR per
/// RFC 7591), so the map needs a ceiling or a flood could exhaust memory. At the
/// cap we evict the soonest-to-expire entry to admit the new one: bounded memory
/// that still self-heals as TTLs lapse.
const CLIENT_CAP: usize = 10_000;

/// Bounded registry of Dynamic-Client-Registration clients: `client_id` → its
/// registered redirect URIs. `/authorize` matches the requested `redirect_uri`
/// against this set exactly, so a client can only be sent an authorization code
/// at a URI it pre-registered (OAuth 2.1 redirect allowlist / RFC 8252).
#[derive(Clone, Default, Debug)]
pub struct ClientRegistry {
    inner: Arc<Mutex<HashMap<String, RegisteredClient>>>,
}

#[derive(Debug, Clone)]
struct RegisteredClient {
    redirect_uris: Vec<String>,
    expires_at: Instant,
}

impl ClientRegistry {
    /// Record a freshly registered client's redirect URIs (validated by the
    /// caller). Evicts expired entries first; if still at the cap, drops the
    /// soonest-to-expire entry so a new registration always lands.
    pub async fn insert(&self, client_id: String, redirect_uris: Vec<String>) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        if map.len() >= CLIENT_CAP && !map.contains_key(&client_id) {
            if let Some(victim) = map
                .iter()
                .min_by_key(|(_, c)| c.expires_at)
                .map(|(id, _)| id.clone())
            {
                map.remove(&victim);
            }
        }
        map.insert(
            client_id,
            RegisteredClient {
                redirect_uris,
                expires_at: Instant::now() + CLIENT_TTL,
            },
        );
    }

    /// The registered redirect URIs for `client_id`, if the registration is
    /// still live. `None` means "unknown client" — `/authorize` rejects it.
    pub async fn redirect_uris(&self, client_id: &str) -> Option<Vec<String>> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.get(client_id).map(|c| c.redirect_uris.clone())
    }

    fn gc(map: &mut HashMap<String, RegisteredClient>) {
        let now = Instant::now();
        map.retain(|_, c| c.expires_at > now);
    }
}
