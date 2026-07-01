use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use url::{Host, Url};
use uuid::Uuid;

use super::super::app_state::AppState;
use super::helpers::oauth_error;

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

/// A redirect URI the gateway will *record* at registration: HTTPS (any host)
/// or an HTTP loopback address (MCP spec §Communication Security). Anything else
/// is rejected up front so the `/authorize` allowlist only holds safe targets.
/// This is the registration gate; `/authorize` additionally requires an exact
/// match against a registered URI (see [`redirect_uri_matches`]).
pub fn is_valid_redirect_uri(raw: &str) -> bool {
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
pub fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
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
}
