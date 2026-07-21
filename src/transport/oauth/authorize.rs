use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::auth::pkce;

use super::super::app_state::AppState;
use super::super::oauth_state::{GrantIdentity, OAuthBridge};
use super::helpers::{build_redirect, oauth_error, random_token, redirect_with_error};
use super::register::{is_loopback_redirect_uri, redirect_uri_matches};

/// Upper bound on a `client_id` the gateway will *adopt* at `/authorize` (as
/// opposed to one it minted at `/register`). `/authorize` is unauthenticated, so
/// without a bound an adversary could stuff arbitrary-length junk into the
/// registry; the store's own cap bounds the row count, this bounds the row size.
/// Comfortably above the 36-char ids `/register` mints.
const MAX_ADOPTABLE_CLIENT_ID: usize = 128;

/// Whether an unregistered `client_id` is shaped like a real one and therefore
/// safe to record verbatim: bounded length, printable ASCII only (no control
/// characters, no whitespace — nothing that would mangle a log line).
fn is_adoptable_client_id(client_id: &str) -> bool {
    client_id.len() <= MAX_ADOPTABLE_CLIENT_ID && client_id.chars().all(|c| c.is_ascii_graphic())
}

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
    let Some(requested_uri) = p.redirect_uri.filter(|u| !u.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        );
    };
    let redirect_uri = match state.client_registry.redirect_uris(client_id).await {
        Some(registered) => {
            if !registered
                .iter()
                .any(|r| redirect_uri_matches(r, &requested_uri))
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri must exactly match a registered redirect URI",
                );
            }
            requested_uri
        }
        // Unknown client_id, loopback redirect: adopt the id rather than
        // dead-end. A client caches its `client_id` and replays it for as long
        // as it stays signed in; if the registration is gone (pre-0008 install,
        // TTL lapsed, state DB restored from a backup) the browser lands on a
        // bare `invalid_client` page with nothing telling it to re-register.
        // Adopting is safe *only* for loopback: the code goes to the user's own
        // machine, so there is no third party to leak it to (RFC 8252 §7.3).
        // An https redirect stays a hard reject — that is the case where waving
        // an unknown client through would let a code be sent to an attacker's
        // host, which is exactly what the allowlist exists to prevent.
        None if is_loopback_redirect_uri(&requested_uri) && is_adoptable_client_id(client_id) => {
            if !state
                .client_registry
                .insert(client_id.to_string(), vec![requested_uri.clone()])
                .await
            {
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "client registration capacity reached; retry later",
                );
            }
            tracing::info!("adopted an unregistered client_id for a loopback redirect");
            requested_uri
        }
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "unknown client_id; register via /register first",
            );
        }
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
    if auth
        .flows
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
        .await
        .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "gateway temporarily overloaded; try again",
        );
    }

    Redirect::to(idp_url.as_str()).into_response()
}

/// Finish an MCP OAuth-bridge login: called by `/auth/callback` when the
/// recovered flow carries [`OAuthBridge`] context. Exchanges the IdP code,
/// mints a one-time authorization code bound to the freshly-issued session
/// JWT + PKCE challenge, and 302s back to the client's redirect URI.
///
/// On any IdP-side failure we still 302 back with an `error` param (never a
/// raw 5xx) so the client's loopback handler completes instead of hanging.
pub async fn complete_bridge_login(
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
    if auth
        .codes
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
        .await
        .is_err()
    {
        // The browser is sitting on /auth/callback and the client's loopback
        // listener is waiting for a redirect. A raw 5xx here would hang it (see
        // the always-redirect contract in this fn's docstring), so 302 back with
        // a valid OAuth error code instead. `temporarily_unavailable` (RFC 6749
        // §4.1.2.1) is the overload signal.
        return redirect_with_error(&bridge, "temporarily_unavailable");
    }

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
