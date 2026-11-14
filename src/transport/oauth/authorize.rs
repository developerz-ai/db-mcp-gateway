use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::auth::pkce;

use super::super::app_state::OAuthState;
use super::helpers::{oauth_error, query_rejected, random_token};
use super::register::{
    is_loopback_redirect_uri, redirect_uri_matches, redirect_uris_acceptable, registry_error,
};
use crate::auth::oauth::OAuthBridge;

/// Upper bound on a `client_id` the gateway will *adopt* at `/authorize` (as
/// opposed to one it minted at `/register`). `/authorize` is unauthenticated, so
/// without a bound an adversary could stuff arbitrary-length junk into the
/// registry; the store's own cap bounds the row count, this bounds the row size.
/// Comfortably above the 36-char ids `/register` mints.
const MAX_ADOPTABLE_CLIENT_ID: usize = 128;

/// Bounds on the client-supplied values `/authorize` stashes for the IdP
/// round-trip. The endpoint is unauthenticated and the pending-flow store holds
/// up to 10,000 entries for 15 minutes, so every stored value needs a ceiling.
/// Real clients send a ~32-byte `state` and their own MCP URL as `resource`.
const MAX_STATE_LEN: usize = 512;
const MAX_RESOURCE_LEN: usize = 512;
/// A PKCE S256 challenge is base64url-no-pad of a SHA-256 digest: exactly 43
/// characters (RFC 7636 §4.2).
const S256_CHALLENGE_LEN: usize = 43;

fn is_s256_challenge(challenge: &str) -> bool {
    challenge.len() == S256_CHALLENGE_LEN
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The first bound a request breaks, as an `invalid_request` description.
fn bounds_violation(
    code_challenge: &str,
    client_state: &str,
    resource: Option<&str>,
) -> Option<&'static str> {
    if !is_s256_challenge(code_challenge) {
        return Some("code_challenge must be a 43-character base64url S256 digest");
    }
    if client_state.len() > MAX_STATE_LEN {
        return Some("state must be at most 512 bytes");
    }
    if resource.is_some_and(|r| r.len() > MAX_RESOURCE_LEN) {
        return Some("resource must be at most 512 bytes");
    }
    None
}

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
    State(state): State<OAuthState>,
    params: Result<Query<AuthorizeParams>, QueryRejection>,
) -> Response {
    let Query(p) = match params {
        Ok(params) => params,
        Err(rejection) => return query_rejected(&rejection),
    };
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
    // Resolve the client now, but record an adopted one only after every
    // other parameter validates: a request that fails PKCE or `state` must
    // leave nothing behind in the registry.
    let (adopt, client_name) = match state.client_registry.lookup(client_id).await {
        Some(registered) => {
            if !registered
                .redirect_uris
                .iter()
                .any(|r| redirect_uri_matches(r, &requested_uri))
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri must exactly match a registered redirect URI",
                );
            }
            (false, registered.client_name)
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
        None if is_loopback_redirect_uri(&requested_uri)
            && redirect_uris_acceptable(std::slice::from_ref(&requested_uri))
            && is_adoptable_client_id(client_id) =>
        {
            (true, None)
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
    if let Some(violation) = bounds_violation(&code_challenge, &client_state, p.resource.as_deref())
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", violation);
    }
    if adopt {
        // `adopt` starts the row on the authorised-client TTL: this
        // `/authorize` is its first use.
        if let Err(err) = state
            .client_registry
            .adopt(client_id.to_string(), requested_uri.clone())
            .await
        {
            return registry_error(err);
        }
        tracing::info!("adopted an unregistered client_id for a loopback redirect");
    }
    let redirect_uri = requested_uri;
    let auth = &state.auth;

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
                client_name,
                client_redirect_uri: redirect_uri,
                client_state,
                code_challenge,
                resource: p.resource,
            },
        )
        .await;

    Redirect::to(idp_url.as_str()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn s256_challenge_shape_is_exact() {
        assert!(is_s256_challenge(CHALLENGE));
        assert!(!is_s256_challenge("abc"));
        assert!(!is_s256_challenge(&format!("{CHALLENGE}A")));
        assert!(!is_s256_challenge(&CHALLENGE.replace('-', "+")));
        assert!(!is_s256_challenge(&"A".repeat(100_000)));
    }

    #[test]
    fn stored_values_are_bounded() {
        assert_eq!(
            bounds_violation(CHALLENGE, "s", Some("https://gw/mcp")),
            None
        );
        let max = "x".repeat(MAX_STATE_LEN);
        assert_eq!(bounds_violation(CHALLENGE, &max, Some(&max)), None);
        let over = "x".repeat(MAX_STATE_LEN + 1);
        assert!(bounds_violation(CHALLENGE, &over, None).is_some_and(|v| v.starts_with("state")));
        assert!(
            bounds_violation(CHALLENGE, "s", Some(&over))
                .is_some_and(|v| v.starts_with("resource"))
        );
        assert!(
            bounds_violation("short", "s", None).is_some_and(|v| v.starts_with("code_challenge"))
        );
    }
}
