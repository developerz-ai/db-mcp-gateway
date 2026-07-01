use axum::http::HeaderMap;
use axum::http::header::HOST;
use axum::response::Response;
use url::{Host, Url};

use super::super::app_state::AppState;
use super::helpers::oauth_error;

/// The single scope the gateway advertises. Authorization is by IdP `groups`
/// claim against the permissions YAML, not OAuth scopes — so one umbrella
/// scope keeps the metadata honest without implying scope-based authz.
pub(super) const MCP_SCOPE: &str = "mcp";

/// Serialize a URL's origin (`scheme://host[:port]`, default ports omitted),
/// or `None` for a non-tuple/opaque origin.
pub(super) fn origin_of(raw: &str) -> Option<String> {
    let origin = Url::parse(raw).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

pub(super) fn is_loopback_host(host: &str) -> bool {
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
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
