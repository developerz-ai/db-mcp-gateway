use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::json;
use url::Url;
use uuid::Uuid;

use super::super::oauth_state::OAuthBridge;

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

pub(super) fn redirect_with_error(bridge: &OAuthBridge, error: &str) -> Response {
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

pub(super) fn random_token() -> String {
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
