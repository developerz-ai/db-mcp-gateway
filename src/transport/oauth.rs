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
//! 4. (optional) `POST /register` → Dynamic Client Registration (RFC 7591).
//! 5. `GET /authorize` (PKCE) → we drive the IdP login, then 302 back to the
//!    client's loopback redirect with a one-time authorization code.
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

use axum::Json;
use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, HOST, PRAGMA};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::Uuid;

use crate::auth::jwt;

use super::app_state::{AppState, OAuthBridge};

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
/// `Host` header when auth isn't wired (tests).
pub(crate) fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(auth) = state.auth.as_ref()
        && let Some(origin) = origin_of(&auth.config.redirect_url)
    {
        return origin;
    }
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
    format!("{scheme}://{host}")
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
    let base = base_url(&state, &headers);
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
    let base = base_url(&state, &headers);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
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

/// `POST /register` — accept any public client and hand back a generated
/// `client_id`. We don't persist a client registry: the real protections are
/// PKCE + the IdP login + the loopback/https redirect-URI check at
/// `/authorize`, none of which depend on a recognized `client_id`. This keeps
/// the friction-free DCR the MCP spec wants without a stateful client store.
pub async fn register(Json(req): Json<RegisterRequest>) -> Response {
    let client_id = format!("mcp-{}", Uuid::new_v4().simple());
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
    #[allow(dead_code)]
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
    // Open-redirect guard (MCP spec §Open Redirection): only loopback or https.
    let Some(redirect_uri) = p.redirect_uri.filter(|u| is_valid_redirect_uri(u)) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required and must be loopback or https",
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

    let Some(auth) = state.auth.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "auth not configured",
        );
    };

    // Drive the IdP login. We reuse the gateway's own registered redirect
    // (`OIDC_REDIRECT_URL` → /auth/callback); the bridge context recovered
    // there tells the callback to mint a code instead of returning JSON.
    let csrf_state = random_token();
    let nonce = random_token();
    let idp_url = match auth.oidc.authorize_url(&csrf_state, &nonce).await {
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
            OAuthBridge {
                client_redirect_uri: redirect_uri,
                client_state: p.state.unwrap_or_default(),
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
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return redirect_with_error(&bridge, "server_error");
    };

    let verified = match auth.oidc.exchange_and_verify(code, nonce).await {
        Ok(v) => v,
        Err(_) => return redirect_with_error(&bridge, "access_denied"),
    };

    let session = match auth
        .sessions
        .create(
            &verified.sub,
            &verified.email,
            &verified.groups,
            auth.config.session_ttl,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(_) => return redirect_with_error(&bridge, "server_error"),
    };

    let access_token = match jwt::issue(
        &auth.config.session_signing_key,
        session.id,
        &verified.sub,
        auth.config.session_ttl,
    ) {
        Ok(t) => t,
        Err(_) => return redirect_with_error(&bridge, "server_error"),
    };

    let auth_code = random_token();
    auth.codes
        .insert(
            auth_code.clone(),
            access_token,
            auth.config.session_ttl.as_secs(),
            bridge.code_challenge.clone(),
            bridge.client_redirect_uri.clone(),
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
        // Redirect URI was validated at /authorize, so this is unreachable in
        // practice; fail closed with a 400 rather than an open redirect.
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
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    #[allow(dead_code)]
    client_id: Option<String>,
}

/// `POST /token` — redeem a one-time authorization code. Verifies the PKCE
/// `code_verifier` against the stored S256 challenge and that the
/// `redirect_uri` matches the one from `/authorize`, then returns the gateway
/// session JWT as the bearer access token.
pub async fn token(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<TokenForm>,
) -> Response {
    if form.grant_type.as_deref() != Some("authorization_code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code is supported",
        );
    }
    let Some(auth) = state.auth.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "auth not configured",
        );
    };
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

    if !verify_pkce(verifier, &entry.code_challenge) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }

    let body = json!({
        "access_token": entry.access_token,
        "token_type": "Bearer",
        "expires_in": entry.expires_in_seconds,
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

/// PKCE S256 check: `base64url-no-pad(SHA256(verifier)) == challenge`, compared
/// in constant time so a mismatch can't be probed byte-by-byte via timing.
fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    ct_eq(computed.as_bytes(), challenge.as_bytes())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Redirect URIs must be a loopback address or HTTPS (MCP spec §Communication
/// Security / §Open Redirection). Anything else is rejected before we trust it.
fn is_valid_redirect_uri(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => {
            matches!(url.host(),
            Some(Host::Domain(d)) if d.eq_ignore_ascii_case("localhost"))
                || matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
                || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
        }
        _ => false,
    }
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
    fn pkce_s256_round_trip() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(verifier, challenge));
        assert!(!verify_pkce("wrong-verifier", challenge));
    }

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
