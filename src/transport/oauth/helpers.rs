use axum::Json;
use axum::extract::rejection::{FormRejection, JsonRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::auth::oauth::OAuthBridge;

pub(super) fn build_redirect(base: &str, params: &[(&str, &str)]) -> Option<String> {
    let mut url = Url::parse(base).ok()?;
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
    }
    Some(url.to_string())
}

pub(in crate::transport) fn redirect_with_error(bridge: &OAuthBridge, error: &str) -> Response {
    match build_redirect(
        &bridge.client_redirect_uri,
        &[("error", error), ("state", bridge.client_state.as_str())],
    ) {
        Some(url) => Redirect::to(&url).into_response(),
        None => oauth_error(StatusCode::BAD_GATEWAY, error, "login failed"),
    }
}

pub(super) fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// RFC 6749 §5.2 shape for a body axum could not decode (wrong content type,
/// unreadable or oversized body), instead of axum's plain-text rejection.
pub(super) fn form_rejected(rejection: &FormRejection) -> Response {
    oauth_error(
        rejection.status(),
        "invalid_request",
        &rejection.body_text(),
    )
}

/// Same as [`form_rejected`], for an undecodable query string.
pub(in crate::transport) fn query_rejected(rejection: &QueryRejection) -> Response {
    oauth_error(
        rejection.status(),
        "invalid_request",
        &rejection.body_text(),
    )
}

/// RFC 7591 §3.2.2 shape for undecodable registration metadata.
pub(super) fn json_rejected(rejection: &JsonRejection) -> Response {
    oauth_error(
        rejection.status(),
        "invalid_client_metadata",
        &rejection.body_text(),
    )
}

/// 128 bits from a CSPRNG (uuid v4): CSRF state, nonces, codes, refresh tokens.
pub(in crate::transport) fn random_token() -> String {
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
