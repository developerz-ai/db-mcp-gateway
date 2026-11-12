//! Fetching the IdP's discovery document and other metadata JSON.

use serde::de::DeserializeOwned;

use super::helpers::require_secure_url;
use super::types::DiscoveryDocument;
use crate::auth::errors::AuthError;

/// Fetch and check the discovery document for `issuer` (no trailing slash).
pub(super) async fn fetch(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<DiscoveryDocument, AuthError> {
    // The configured issuer must be https (else discovery, code exchange,
    // and client_secret travel in plaintext — A4). Loopback http is allowed
    // for local dev / mock IdPs.
    require_secure_url(issuer)?;
    let url = format!("{issuer}/.well-known/openid-configuration");
    let doc: DiscoveryDocument = get_json(http, &url).await?;

    // Issuer per OIDC §4: must match the one we asked for. Stops a tampered
    // discovery doc from quietly pointing us at a different IdP.
    if doc.issuer.trim_end_matches('/') != issuer {
        return Err(AuthError::Discovery);
    }

    // A discovery doc can repoint us at http endpoints even when the issuer
    // is https; reject any non-https (non-loopback) endpoint before we ever
    // POST the code + client_secret to it (A4).
    require_secure_url(&doc.authorization_endpoint)?;
    require_secure_url(&doc.token_endpoint)?;
    require_secure_url(&doc.jwks_uri)?;
    Ok(doc)
}

/// GET `url` as JSON. Every failure is `Discovery`: the IdP's metadata is
/// unreachable or malformed, and the URL may carry nothing worth logging.
pub(super) async fn get_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
) -> Result<T, AuthError> {
    http.get(url)
        .send()
        .await
        .map_err(|_| AuthError::Discovery)?
        .error_for_status()
        .map_err(|_| AuthError::Discovery)?
        .json()
        .await
        .map_err(|_| AuthError::Discovery)
}
