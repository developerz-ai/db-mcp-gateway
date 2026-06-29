//! MCP OAuth bridge — makes the gateway speak the MCP Authorization spec
//! (2025-06-18) so spec-compliant clients (Claude Code, Cursor, …) can log in
//! with zero manual credential wiring.
//!
//! The gateway already runs a full OIDC Relying-Party dance against the org's
//! IdP (`/auth/login` → IdP → `/auth/callback` → gateway session JWT). That
//! flow is *bespoke*: the agent POSTs `/auth/login`, reads a JSON session
//! token, and sends it as a bearer. MCP clients don't speak that — on a `401`
//! they follow OAuth 2.1 discovery:
//!
//! 1. `401` carries `WWW-Authenticate: Bearer resource_metadata="…"` (RFC 9728).
//! 2. `GET /.well-known/oauth-protected-resource` → the resource's metadata,
//!    naming this gateway as its own authorization server.
//! 3. `GET /.well-known/oauth-authorization-server` → AS metadata (RFC 8414).
//! 4. `POST /register` → Dynamic Client Registration (RFC 7591); pins the
//!    client's redirect-URI allowlist so step 5 can match against it.
//! 5. `GET /authorize` (PKCE) → we drive the IdP login, then 302 back to the
//!    client's *registered* redirect with a one-time authorization code.
//! 6. `POST /token` (PKCE verifier) → we hand back the gateway session JWT as
//!    the OAuth `access_token`.
//!
//! This module is a thin *front* over the existing `auth::oidc` + session
//! machinery: the access token IS the same HS256 session JWT the bespoke flow
//! issues, so the bearer middleware, revocation, and audit are all unchanged.
//! Because the token is signed with the gateway-private key and only ever
//! minted for this resource, the RFC 8707 audience requirement ("only accept
//! tokens issued for us") is satisfied structurally — no other party can mint
//! a valid-signature bearer.

use std::time::Instant;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, HOST, PRAGMA};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::json;
use url::{Host, Url};
use uuid::Uuid;

use crate::auth::{jwt, pkce};

use super::app_state::{AppState, AuthFacade};
use super::oauth_state::{GrantIdentity, OAuthBridge};

/// The single scope the gateway advertises. Authorization is by IdP `groups`
/// claim against the permissions YAML, not OAuth scopes — so one umbrella
/// scope keeps the metadata honest without implying scope-based authz.
const MCP_SCOPE: &str = "mcp";

// ---------------------------------------------------------------------------
// Base-URL + metadata-URL helpers (shared with the bearer middleware).
// ---------------------------------------------------------------------------

/// Serialize a URL's origin (`scheme://host[:port]`, default ports omitted),
/// or `None` for a non-tuple/opaque origin.
fn origin_of(raw: &str) -> Option<String> {
    let origin = Url::parse(raw).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

fn is_loopback_host(host: &str) -> bool {
    let bare = host.split(':').next().unwrap_or(host);
    match Host::parse(bare) {
        Ok(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Ok(Host::Ipv4(ip)) => ip.is_loopback(),
        Ok(Host::Ipv6(ip)) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// The gateway's external base URL. Authoritative source is the configured
/// `OIDC_REDIRECT_URL` origin — the one URL we *know* the public edge resolves
/// to (the IdP redirects a real browser there). Falls back to the request
/// `Host` header when auth isn't wired (tests). Fails closed (500) if auth is
/// configured but the `OIDC_REDIRECT_URL` is unparseable.
pub(crate) fn base_url(state: &AppState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    if let Some(auth) = state.auth.as_ref() {
        match origin_of(&auth.config.redirect_url) {
            Some(origin) => return Ok(origin),
            None => {
                // Configured redirect_url is not parseable; fail closed rather
                // than falling back to the untrusted Host header.
                return Err(Box::new(oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "configured redirect_url is invalid",
                )));
            }
        }
    }

    // Auth not configured; fall back to Host header (tests only).
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if is_loopback_host(host) {
                "http".to_string()
            } else {
                "https".to_string()
            }
        });
    Ok(format!("{scheme}://{host}"))
}

/// RFC 9728 Protected Resource Metadata URL for a given base.
pub(crate) fn resource_metadata_url(base: &str) -> String {
    format!("{base}/.well-known/oauth-protected-resource")
}

// ---------------------------------------------------------------------------
// Discovery metadata (RFC 9728 + RFC 8414).
// ---------------------------------------------------------------------------

/// `GET /.well-known/oauth-protected-resource[/…]` — names this gateway as its
/// own authorization server. Mounted at both the bare path and the
/// `mcp_path`-suffixed path so clients that key the well-known by resource path
/// (RFC 9728 §3.1) find it either way.
pub async fn protected_resource_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let base = match base_url(&state, &headers) {
        Ok(b) => b,
        Err(e) => return *e,
    };
    let resource = format!("{}{}", base, state.mcp_path);
    Json(json!({
        "resource": resource,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [MCP_SCOPE],
    }))
    .into_response()
}

/// `GET /.well-known/oauth-authorization-server` (and an `openid-configuration`
/// alias) — RFC 8414 metadata pointing at this gateway's bridge endpoints.
pub async fn authorization_server_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let base = match base_url(&state, &headers) {
        Ok(b) => b,
        Err(e) => return *e,
    };
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [MCP_SCOPE],
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
}

/// `POST /register` — Dynamic Client Registration (RFC 7591). Accept any public
/// client, validate its redirect URIs (loopback or https), persist them under a
/// generated `client_id`, and hand the id back. `/authorize` later requires the
/// requested `redirect_uri` to exactly match one registered here, so DCR is the
/// step that pins a client's redirect allowlist. The store is bounded (TTL+cap)
/// because this endpoint is unauthenticated.
pub async fn register(State(state): State<AppState>, Json(req): Json<RegisterRequest>) -> Response {
    // RFC 7591 §3.2.1: reject unusable redirect URIs at registration so the
    // /authorize allowlist only ever holds loopback/https targets.
    if req.redirect_uris.is_empty() || !req.redirect_uris.iter().all(|u| is_valid_redirect_uri(u)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must be non-empty; each loopback or https",
        );
    }
    let client_id = format!("mcp-{}", Uuid::new_v4().simple());
    // The registry is bounded and fails closed at capacity (never evicts a live
    // client, since /register is unauthenticated). At the cap, refuse rather
    // than displacing a legitimate client mid-/authorize.
    if !state
        .client_registry
        .insert(client_id.clone(), req.redirect_uris.clone())
        .await
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "client registration capacity reached; retry later",
        );
    }
    let mut body = json!({
        "client_id": client_id,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });
    if let Some(name) = req.client_name {
        body["client_name"] = json!(name);
    }
    (StatusCode::CREATED, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Authorization endpoint.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
    resource: Option<String>,
}

/// `GET /authorize` — validate the OAuth 2.1 + PKCE request, stash the client's
/// redirect/state/challenge, and 302 the browser into the IdP login. The IdP
/// lands back at `/auth/callback`, which calls `complete_bridge_login`.
pub async fn authorize(
    State(state): State<AppState>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    if p.response_type.as_deref() != Some("code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    // Exact-match redirect allowlist (OAuth 2.1 §redirect_uri / RFC 8252): the
    // client must have pre-registered via /register, and the requested
    // redirect_uri must match one of its registered URIs. Replaces the old
    // accept-any-https check, which let a code be sent to an arbitrary host.
    let Some(client_id) = p.client_id.as_deref().filter(|c| !c.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };
    let Some(registered) = state.client_registry.redirect_uris(client_id).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "unknown client_id; register via /register first",
        );
    };
    let Some(redirect_uri) = p
        .redirect_uri
        .filter(|u| registered.iter().any(|r| redirect_uri_matches(r, u)))
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri must exactly match a registered redirect URI",
        );
    };
    // PKCE is mandatory (OAuth 2.1 §7.5.2). Only S256 — never plain.
    let Some(code_challenge) = p.code_challenge.filter(|c| !c.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge is required (PKCE)",
        );
    };
    if p.code_challenge_method.as_deref() != Some("S256") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }
    // `state` is the client's CSRF token; we echo it back verbatim on the 302.
    // Require it (non-empty) rather than defaulting to "" — an absent `state`
    // leaves the client with no value to bind its callback against. Mirrors the
    // code_challenge rejection above.
    let Some(client_state) = p.state.filter(|s| !s.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "state is required",
        );
    };

    let Some(auth) = state.auth.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "auth not configured",
        );
    };

    // Drive the IdP login. We reuse the gateway's own registered redirect
    // (`OIDC_REDIRECT_URL` → /auth/callback); the bridge context recovered
    // there tells the callback to mint a code instead of returning JSON. The
    // gateway runs its *own* PKCE against the IdP (separate from the client's
    // `code_challenge` above) since IdPs increasingly require it.
    let csrf_state = random_token();
    let nonce = random_token();
    let (idp_verifier, idp_challenge) = pkce::generate();
    let idp_url = match auth
        .oidc
        .authorize_url(&csrf_state, &nonce, &idp_challenge)
        .await
    {
        Ok(url) => url,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "could not reach the identity provider",
            );
        }
    };
    auth.flows
        .insert_bridge(
            csrf_state,
            nonce,
            idp_verifier,
            OAuthBridge {
                client_id: client_id.to_owned(),
                client_redirect_uri: redirect_uri,
                client_state,
                code_challenge,
                resource: p.resource,
            },
        )
        .await;

    Redirect::to(idp_url.as_str()).into_response()
}

/// Finish an MCP OAuth-bridge login: called by `/auth/callback` when the
/// recovered flow carries [`OAuthBridge`] context. Exchanges the IdP code,
/// mints a one-time authorization code bound to the freshly-issued session
/// JWT + PKCE challenge, and 302s back to the client's redirect URI.
///
/// On any IdP-side failure we still 302 back with an `error` param (never a
/// raw 5xx) so the client's loopback handler completes instead of hanging.
pub(super) async fn complete_bridge_login(
    state: &AppState,
    bridge: OAuthBridge,
    code: &str,
    nonce: &str,
    idp_verifier: &str,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return redirect_with_error(&bridge, "server_error");
    };

    let verified = match auth
        .oidc
        .exchange_and_verify(code, nonce, idp_verifier)
        .await
    {
        Ok(v) => v,
        Err(_) => return redirect_with_error(&bridge, "access_denied"),
    };

    // Don't mint a session yet — only stash the verified identity. The session
    // + access/refresh tokens are issued when the code is redeemed at `/token`,
    // so an abandoned login leaves no orphan session row.
    let auth_code = random_token();
    auth.codes
        .insert(
            &auth_code,
            GrantIdentity {
                sub: verified.sub,
                email: verified.email,
                groups: verified.groups,
            },
            bridge.code_challenge.clone(),
            bridge.client_redirect_uri.clone(),
            bridge.client_id.clone(),
        )
        .await;

    match build_redirect(
        &bridge.client_redirect_uri,
        &[
            ("code", auth_code.as_str()),
            ("state", bridge.client_state.as_str()),
        ],
    ) {
        Some(url) => Redirect::to(&url).into_response(),
        // The 302 target is the registry-matched URI stashed at /authorize, so
        // this is unreachable in practice; fail closed with a 400 rather than an
        // open redirect.
        None => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        ),
    }
}

// ---------------------------------------------------------------------------
// Token endpoint.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: Option<String>,
    // authorization_code grant:
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    // refresh_token grant:
    refresh_token: Option<String>,
    /// RFC 6749 §3.2.1: public clients SHOULD send `client_id`; when present,
    /// verify it matches the registered client that obtained the authorization
    /// code (prevents code-injection across clients).
    client_id: Option<String>,
}

/// `POST /token` — redeem an authorization code or a refresh token. For
/// `authorization_code`, verifies the PKCE `code_verifier` against the stored
/// S256 challenge and the `redirect_uri` match; for `refresh_token`, rotates
/// the token. Both mint a fresh gateway session and return the session JWT as
/// the bearer access token plus a new refresh token.
pub async fn token(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<TokenForm>,
) -> Response {
    // Validate the grant before touching auth state so a malformed request is a
    // clean 400 regardless of wiring.
    let grant = form.grant_type.as_deref();
    if grant != Some("authorization_code") && grant != Some("refresh_token") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "supported grant types: authorization_code, refresh_token",
        );
    }
    let Some(auth) = state.auth.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "auth not configured",
        );
    };
    if grant == Some("refresh_token") {
        token_refresh(auth, form).await
    } else {
        token_authorization_code(auth, form).await
    }
}

async fn token_authorization_code(auth: &AuthFacade, form: TokenForm) -> Response {
    let (Some(code), Some(verifier)) = (form.code.as_deref(), form.code_verifier.as_deref()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and code_verifier are required",
        );
    };

    // One-time: take() removes the code so a replay finds nothing.
    let Some(entry) = auth.codes.take(code).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code is invalid or expired",
        );
    };

    // client_id, when sent, must match the registrant (RFC 6749 §3.2.1).
    // Public clients aren't authenticated by secret, but binding the code to
    // its originating client_id prevents cross-client code-injection.
    if let Some(sent) = form.client_id.as_deref()
        && sent != entry.client_id
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
    }

    // redirect_uri, when sent, must match the authorize-time value (OAuth 2.1).
    if let Some(sent) = form.redirect_uri.as_deref()
        && sent != entry.redirect_uri
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }

    if !pkce::verify(verifier, &entry.code_challenge) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }

    // Fresh authorization → fresh refresh-token chain (no carried birth time).
    issue_token_response(auth, entry.identity, None).await
}

async fn token_refresh(auth: &AuthFacade, form: TokenForm) -> Response {
    let Some(token) = form.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    // Rotation: take() consumes the presented token; `issue_token_response`
    // mints a fresh one. A replayed (already-rotated) token finds nothing.
    let Some(entry) = auth.refresh.take(token).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token is invalid or expired",
        );
    };
    // Carry the chain's original birth time so rotation renews the token value
    // but never extends the absolute TTL. `entry.identity` (groups included) is
    // the one frozen at the original browser login, so this same cap also bounds
    // how long a since-revoked group keeps minting sessions (O3b): the chain dies
    // REFRESH_TTL after the first mint, forcing a fresh `/authorize` that
    // re-reads groups from the IdP.
    let issued_at = entry.issued_at;
    issue_token_response(auth, entry.identity, Some(issued_at)).await
}

/// Mint a fresh session for `identity`, issue the session JWT as the access
/// token, mint+store a rotating refresh token, and render the OAuth token
/// response (with `Cache-Control: no-store`).
///
/// `chain_issued_at` is `None` for a fresh authorization (the new refresh token
/// starts its own chain) and `Some(birth)` for a rotation (the new token
/// inherits the chain's original mint time so the absolute TTL doesn't slide).
async fn issue_token_response(
    auth: &AuthFacade,
    identity: GrantIdentity,
    chain_issued_at: Option<Instant>,
) -> Response {
    let session = match auth
        .sessions
        .create(
            &identity.sub,
            &identity.email,
            &identity.groups,
            auth.config.session_ttl,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not create session",
            );
        }
    };
    let access_token = match jwt::issue(
        &auth.config.session_signing_key,
        session.id,
        &identity.sub,
        auth.config.session_ttl,
    ) {
        Ok(t) => t,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not issue token",
            );
        }
    };
    let refresh_token = random_token();
    match chain_issued_at {
        Some(issued_at) => {
            auth.refresh
                .insert_rotated(&refresh_token, identity, issued_at)
                .await
        }
        None => auth.refresh.insert(&refresh_token, identity).await,
    }

    let body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": auth.config.session_ttl.as_secs(),
        "refresh_token": refresh_token,
        "scope": MCP_SCOPE,
    });
    // OAuth 2.1 §Token Response: token responses must not be cached.
    (
        StatusCode::OK,
        [(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")],
        Json(body),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// A redirect URI the gateway will *record* at registration: HTTPS (any host)
/// or an HTTP loopback address (MCP spec §Communication Security). Anything else
/// is rejected up front so the `/authorize` allowlist only holds safe targets.
/// This is the registration gate; `/authorize` additionally requires an exact
/// match against a registered URI (see [`redirect_uri_matches`]).
fn is_valid_redirect_uri(raw: &str) -> bool {
    match Url::parse(raw) {
        Ok(url) => url.scheme() == "https" || is_http_loopback(&url),
        Err(_) => false,
    }
}

/// An `http://` URL whose host is a loopback address (`localhost`, `127.0.0.0/8`,
/// or `::1`).
fn is_http_loopback(url: &Url) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Match a requested redirect URI against a registered one. OAuth 2.1 mandates
/// exact string comparison; RFC 8252 §7.3 adds one carve-out — a native client
/// binds an ephemeral loopback port at request time, so for loopback URIs every
/// component *except the port* must match. A loopback URI targets the user's own
/// machine, so port-flexibility there leaks nothing to a third party.
fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(reg), Ok(req)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    is_http_loopback(&reg)
        && is_http_loopback(&req)
        && reg.host() == req.host()
        && reg.username() == req.username()
        && reg.password() == req.password()
        && reg.path() == req.path()
        && reg.query() == req.query()
        && reg.fragment() == req.fragment()
}

fn build_redirect(base: &str, params: &[(&str, &str)]) -> Option<String> {
    let mut url = Url::parse(base).ok()?;
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
    }
    Some(url.to_string())
}

fn redirect_with_error(bridge: &OAuthBridge, error: &str) -> Response {
    match build_redirect(
        &bridge.client_redirect_uri,
        &[("error", error), ("state", bridge.client_state.as_str())],
    ) {
        Some(url) => Redirect::to(&url).into_response(),
        None => oauth_error(StatusCode::BAD_GATEWAY, error, "login failed"),
    }
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn random_token() -> String {
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rules() {
        assert!(is_valid_redirect_uri("http://127.0.0.1:8080/callback"));
        assert!(is_valid_redirect_uri("http://localhost:1234/cb"));
        assert!(is_valid_redirect_uri("http://[::1]:9/cb"));
        assert!(is_valid_redirect_uri("https://app.example.com/cb"));
        assert!(!is_valid_redirect_uri("http://evil.example.com/cb"));
        assert!(!is_valid_redirect_uri("ftp://localhost/cb"));
        assert!(!is_valid_redirect_uri("not a url"));
    }

    #[test]
    fn redirect_match_is_exact_except_loopback_port() {
        // https: exact string match only.
        assert!(redirect_uri_matches(
            "https://app.example.com/cb",
            "https://app.example.com/cb"
        ));
        assert!(!redirect_uri_matches(
            "https://app.example.com/cb",
            "https://evil.example.com/cb"
        ));
        assert!(!redirect_uri_matches(
            "https://app.example.com/cb",
            "https://app.example.com/other"
        ));
        // Loopback: port may vary (RFC 8252 §7.3); host + path must still match.
        assert!(redirect_uri_matches(
            "http://127.0.0.1:1111/cb",
            "http://127.0.0.1:2222/cb"
        ));
        assert!(redirect_uri_matches(
            "http://localhost/cb",
            "http://localhost:54321/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:1111/cb",
            "http://127.0.0.1:2222/evil"
        ));
        // Port-flex does not bridge distinct loopback hosts or schemes.
        assert!(!redirect_uri_matches(
            "http://localhost/cb",
            "http://127.0.0.1/cb"
        ));
        assert!(!redirect_uri_matches(
            "https://localhost/cb",
            "http://localhost:9/cb"
        ));
        // Loopback port-flex is the *only* carve-out: userinfo and fragment must
        // still match exactly, not just host/path/query.
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:1111/cb",
            "http://user@127.0.0.1:2222/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://user:pass@127.0.0.1:1111/cb",
            "http://user:other@127.0.0.1:2222/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:1111/cb",
            "http://127.0.0.1:2222/cb#frag"
        ));
    }

    #[test]
    fn origin_strips_path_and_default_port() {
        assert_eq!(
            origin_of("https://db-mcp.example.com/auth/callback").as_deref(),
            Some("https://db-mcp.example.com")
        );
        assert_eq!(
            origin_of("http://localhost:8443/auth/callback").as_deref(),
            Some("http://localhost:8443")
        );
    }

    #[test]
    fn build_redirect_appends_query() {
        let url = build_redirect(
            "http://127.0.0.1:9/cb",
            &[("code", "abc"), ("state", "xyz")],
        )
        .expect("valid");
        assert!(url.starts_with("http://127.0.0.1:9/cb?"));
        assert!(url.contains("code=abc"));
        assert!(url.contains("state=xyz"));
    }
}
