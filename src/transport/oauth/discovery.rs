use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::super::app_state::AppState;

use super::urls::{MCP_SCOPE, base_url};

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
        "revocation_endpoint": format!("{base}/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [MCP_SCOPE],
    }))
    .into_response()
}
