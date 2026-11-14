//! The OAuth bridge's return leg: `/auth/callback` hands a verified IdP login
//! here, and it ends in a one-time authorization code on the client's redirect
//! — directly for a loopback redirect, after the user's consent otherwise.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use super::consent::request_consent;
use super::helpers::{build_redirect, oauth_error, random_token, redirect_with_error};
use super::register::is_loopback_redirect_uri;
use crate::auth::oauth::{AuthFacade, GrantIdentity, OAuthBridge};

/// Finish an MCP OAuth-bridge login: called by `/auth/callback` when the
/// recovered flow carries [`OAuthBridge`] context. Exchanges the IdP code, then
/// releases an authorization code to the client's redirect URI — at once for a
/// loopback redirect, or via the consent page for any other.
///
/// On any IdP-side failure we still 302 back with an `error` param (never a
/// raw 5xx) so the client's loopback handler completes instead of hanging.
pub async fn complete_bridge_login(
    auth: &AuthFacade,
    bridge: OAuthBridge,
    code: &str,
    nonce: &str,
    idp_verifier: &str,
) -> Response {
    let verified = match auth
        .oidc
        .exchange_and_verify(code, nonce, idp_verifier)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            // Log the typed reason. `access_denied` is all the client may learn
            // (it can't be told whether the IdP was slow, the nonce mismatched,
            // or the email was unverified), which left this the one login
            // failure with no server-side trace at all — an operator saw a user
            // bounced with `access_denied` and had nothing to correlate. Every
            // `AuthError` Display is secret-free by construction (see
            // `auth::errors`), so the variant is safe to record.
            tracing::warn!(reason = %err, "bridge login failed at the IdP exchange");
            return redirect_with_error(&bridge, "access_denied");
        }
    };
    let identity = GrantIdentity {
        sub: verified.sub,
        email: verified.email,
        groups: verified.groups,
    };
    // The IdP's consent covers only the gateway's own static client, not the
    // dynamically registered one that will receive the code. A loopback
    // redirect can only reach the user's own machine (RFC 8252 §7.3), so it
    // needs no second prompt; anything else does (MCP "confused deputy").
    if is_loopback_redirect_uri(&bridge.client_redirect_uri) {
        return issue_code(auth, identity, &bridge).await;
    }
    request_consent(auth, identity, bridge).await
}

/// Mint a one-time authorization code bound to the verified identity, the PKCE
/// challenge and the client, and 302 it to the client's redirect URI.
pub(super) async fn issue_code(
    auth: &AuthFacade,
    identity: GrantIdentity,
    bridge: &OAuthBridge,
) -> Response {
    // Don't mint a session yet — only stash the verified identity. The session
    // + access/refresh tokens are issued when the code is redeemed at `/token`,
    // so an abandoned login leaves no orphan session row.
    let auth_code = random_token();
    if auth
        .codes
        .insert(
            &auth_code,
            identity,
            bridge.code_challenge.clone(),
            bridge.client_redirect_uri.clone(),
            bridge.client_id.clone(),
        )
        .await
        .is_err()
    {
        // The browser is waiting to be sent back to the client. A raw 5xx here
        // would strand its listener (see the always-redirect contract on
        // `complete_bridge_login`), so 302 back with a valid OAuth error code
        // instead. `temporarily_unavailable` (RFC 6749 §4.1.2.1) is the
        // overload signal.
        return redirect_with_error(bridge, "temporarily_unavailable");
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
