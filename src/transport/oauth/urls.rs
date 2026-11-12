use axum::http::StatusCode;
use axum::response::Response;
use url::Url;

use super::super::app_state::OAuthState;
use super::helpers::oauth_error;

/// The single scope the gateway advertises. Authorization is by IdP `groups`
/// claim against the permissions YAML, not OAuth scopes — so one umbrella
/// scope keeps the metadata honest without implying scope-based authz.
pub(super) const MCP_SCOPE: &str = "mcp";

/// Serialize a URL's origin (`scheme://host[:port]`, default ports omitted),
/// or `None` for a non-tuple/opaque origin.
fn origin_of(raw: &str) -> Option<String> {
    let origin = Url::parse(raw).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The gateway's external base URL: the origin of the configured
/// `OIDC_REDIRECT_URL` — the one URL we *know* the public edge resolves to
/// (the IdP redirects a real browser there). Never the request `Host` header,
/// which the client controls. Fails closed (500) when that URL is unparseable.
pub(crate) fn base_url(state: &OAuthState) -> Result<String, Box<Response>> {
    origin_of(&state.auth.config.redirect_url).ok_or_else(|| {
        Box::new(oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "configured redirect_url is invalid",
        ))
    })
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
        assert_eq!(origin_of("not a url"), None);
    }
}
