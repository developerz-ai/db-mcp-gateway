use std::time::Duration;

use url::{Host, Url};

use super::super::errors::AuthError;

pub(super) const SCOPES: &str = "openid email profile groups";

/// JWKS cache lifetime. Keeps the IdP load low while bounding rotation lag.
pub(super) const JWKS_TTL: Duration = Duration::from_secs(3600);

/// Require an OIDC URL to use `https`, permitting `http` only for loopback
/// hosts (localhost / 127.0.0.0/8 / ::1) so dev and mock IdPs keep working.
/// Surfaced as `Discovery` since it gates the discovery / token-exchange URLs.
pub(super) fn require_secure_url(raw: &str) -> Result<(), AuthError> {
    let url = Url::parse(raw).map_err(|_| AuthError::Discovery)?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&url) => Ok(()),
        _ => Err(AuthError::Discovery),
    }
}

/// Interpret an OIDC boolean-ish claim. OIDC Core §5.1 types `email_verified`
/// as a JSON boolean, but some IdPs (older Google, Azure AD) emit the string
/// `"true"`. Accept either; everything else — `false`, a number, null, absent —
/// is treated as not-true.
pub(super) fn claim_is_true(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

pub(super) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_url_accepted() {
        assert!(require_secure_url("https://idp.example.com/").is_ok());
    }

    #[test]
    fn http_non_loopback_rejected() {
        assert!(require_secure_url("http://idp.example.com/").is_err());
    }

    #[test]
    fn http_loopback_allowed() {
        assert!(require_secure_url("http://localhost:8443/").is_ok());
        assert!(require_secure_url("http://127.0.0.1:8443/").is_ok());
        assert!(require_secure_url("http://[::1]:8443/").is_ok());
    }

    #[test]
    fn email_verified_bool_true_is_true() {
        assert!(claim_is_true(Some(&serde_json::json!(true))));
    }

    #[test]
    fn email_verified_string_true_is_true() {
        // Older Google / Azure AD emit the string form; accept it case-insensitively.
        assert!(claim_is_true(Some(&serde_json::json!("true"))));
        assert!(claim_is_true(Some(&serde_json::json!("TRUE"))));
    }

    #[test]
    fn email_verified_false_or_absent_is_not_true() {
        assert!(!claim_is_true(Some(&serde_json::json!(false))));
        assert!(!claim_is_true(Some(&serde_json::json!("false"))));
        assert!(!claim_is_true(Some(&serde_json::json!("yes"))));
        assert!(!claim_is_true(Some(&serde_json::json!(1))));
        assert!(!claim_is_true(Some(&serde_json::Value::Null)));
        assert!(!claim_is_true(None));
    }
}
