//! RFC 8707 resource indicators. The gateway is the authorization server for
//! exactly one resource — its own MCP endpoint — so a request naming any
//! other is asking for a token this server cannot issue.

use axum::http::StatusCode;
use axum::response::Response;
use url::Url;

use super::super::app_state::OAuthState;
use super::helpers::oauth_error;

/// The `invalid_target` answer (RFC 8707 §2) when `requested` is present and
/// is not this gateway's MCP endpoint; `None` when the request may proceed.
pub(super) fn refusal(state: &OAuthState, requested: Option<&str>) -> Option<Response> {
    let requested = requested?;
    if names_gateway(&state.auth.config.redirect_url, &state.mcp_path, requested) {
        return None;
    }
    Some(oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_target",
        "resource must be this gateway's MCP endpoint",
    ))
}

/// Whether `requested` is `<gateway origin><mcp_path>`. The origin is that of
/// `OIDC_REDIRECT_URL`, as in the discovery metadata. Compared as parsed URLs,
/// so host case and a default port do not matter; neither does a trailing
/// slash. A fragment is never a resource (RFC 8707 §2).
fn names_gateway(redirect_url: &str, mcp_path: &str, requested: &str) -> bool {
    let (Ok(gateway), Ok(requested)) = (Url::parse(redirect_url), Url::parse(requested)) else {
        return false;
    };
    let origin = gateway.origin();
    origin.is_tuple()
        && requested.origin() == origin
        && requested.fragment().is_none()
        && requested.path().trim_matches('/') == mcp_path.trim_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIRECT: &str = "https://db.example.com/auth/callback";

    #[test]
    fn the_advertised_resource_is_accepted() {
        for requested in [
            "https://db.example.com/mcp",
            "https://db.example.com/mcp/",
            "https://DB.example.com:443/mcp",
        ] {
            assert!(names_gateway(REDIRECT, "/mcp", requested), "{requested}");
        }
        assert!(names_gateway(
            "http://127.0.0.1:8443/auth/callback",
            "mcp",
            "http://127.0.0.1:8443/mcp"
        ));
    }

    #[test]
    fn any_other_resource_is_refused() {
        for requested in [
            "https://other.example.com/mcp",
            "http://db.example.com/mcp",
            "https://db.example.com:8443/mcp",
            "https://db.example.com/",
            "https://db.example.com/mcp/extra",
            "https://db.example.com/admin",
            "https://db.example.com/mcp#frag",
            "https://db.example.com.evil.example/mcp",
            "/mcp",
            "not a url",
            "",
        ] {
            assert!(!names_gateway(REDIRECT, "/mcp", requested), "{requested}");
        }
    }

    #[test]
    fn an_unparseable_gateway_url_matches_nothing() {
        assert!(!names_gateway(
            "not a url",
            "/mcp",
            "https://db.example.com/mcp"
        ));
    }
}
