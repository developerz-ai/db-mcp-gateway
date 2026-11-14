use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use url::{Host, Url};
use uuid::Uuid;

use super::super::app_state::OAuthState;
use super::helpers::{json_rejected, oauth_error};
use crate::auth::oauth::StoreError;

/// Most redirect URIs one registration may pin. Real clients send one or two
/// (a loopback callback per port strategy); the cap bounds what an
/// unauthenticated caller can make the registry store.
const MAX_REDIRECT_URIS: usize = 8;
/// Longest redirect URI accepted — well past any real callback URL.
const MAX_REDIRECT_URI_LEN: usize = 2048;

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
pub async fn register(
    State(state): State<OAuthState>,
    req: Result<Json<RegisterRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(rejection) => return json_rejected(&rejection),
    };
    // RFC 7591 §3.2.1: reject unusable redirect URIs at registration so the
    // /authorize allowlist only ever holds bounded loopback/https targets.
    if !redirect_uris_acceptable(&req.redirect_uris) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must hold 1-8 URIs of at most 2048 bytes; each loopback or https, without a fragment",
        );
    }
    let client_id = format!("mcp-{}", Uuid::new_v4().simple());
    if let Err(err) = state
        .client_registry
        .insert(client_id.clone(), req.redirect_uris.clone())
        .await
    {
        return registry_error(err);
    }
    let mut body = json!({
        "client_id": client_id,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    });
    if let Some(name) = req.client_name {
        body["client_name"] = json!(name);
    }
    (StatusCode::CREATED, Json(body)).into_response()
}

/// A failed registry write, as the client sees it. Both are retryable 503s
/// with distinct descriptions: a registry full of authorised clients, or an
/// unreachable state DB.
pub(super) fn registry_error(err: StoreError) -> Response {
    match err {
        StoreError::StoreFull => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "client registration capacity reached; retry later",
        ),
        StoreError::Backend => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "client registration is temporarily unavailable; retry",
        ),
    }
}

pub(super) fn redirect_uris_acceptable(uris: &[String]) -> bool {
    (1..=MAX_REDIRECT_URIS).contains(&uris.len())
        && uris
            .iter()
            .all(|u| u.len() <= MAX_REDIRECT_URI_LEN && is_valid_redirect_uri(u))
}

/// A redirect URI the gateway will *record* at registration: HTTPS (any host)
/// or an HTTP loopback address (MCP spec §Communication Security), with no
/// fragment (RFC 6749 §3.1.2). Anything else is rejected up front so the
/// `/authorize` allowlist only holds safe targets.
/// This is the registration gate; `/authorize` additionally requires an exact
/// match against a registered URI (see [`redirect_uri_matches`]).
pub fn is_valid_redirect_uri(raw: &str) -> bool {
    match Url::parse(raw) {
        Ok(url) => url.fragment().is_none() && (url.scheme() == "https" || is_http_loopback(&url)),
        Err(_) => false,
    }
}

/// Whether `raw` is an `http://` loopback redirect URI — i.e. one that can only
/// deliver an authorization code to the user's *own* machine. `/authorize`
/// leans on this to adopt an unknown `client_id` without weakening the redirect
/// allowlist: there is no third party such a code could leak to.
pub fn is_loopback_redirect_uri(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|url| is_http_loopback(&url))
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

    /// RFC 6749 §3.1.2: a redirection endpoint URI MUST NOT include a
    /// fragment component — not even an empty one.
    #[test]
    fn redirect_uri_with_fragment_is_rejected() {
        assert!(!is_valid_redirect_uri("https://app.example.com/cb#frag"));
        assert!(!is_valid_redirect_uri("https://app.example.com/cb#"));
        assert!(!is_valid_redirect_uri("http://127.0.0.1:9/cb#x"));
        assert!(!redirect_uris_acceptable(&[
            "http://localhost:9/cb#a".to_string()
        ]));
    }

    #[test]
    fn registration_bounds_redirect_uri_count_and_length() {
        let one = "http://127.0.0.1:9/cb".to_string();
        assert!(redirect_uris_acceptable(std::slice::from_ref(&one)));
        assert!(!redirect_uris_acceptable(&[]));
        assert!(!redirect_uris_acceptable(&vec![one; MAX_REDIRECT_URIS + 1]));
        let long = format!(
            "https://app.example.com/{}",
            "a".repeat(MAX_REDIRECT_URI_LEN)
        );
        assert!(!redirect_uris_acceptable(&[long]));
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
