//! Minimal OIDC Relying Party.
//!
//! Hand-rolled to keep the auth surface readable for review. We lean on
//! `jsonwebtoken` for the crypto (signature, alg, exp) — the historically
//! risky bits — and validate `iss` / `aud` / `nonce` / `kid` ourselves.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use super::config::AuthConfig;
use super::errors::AuthError;

const SCOPES: &str = "openid email profile groups";

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// Verified ID-token payload, narrowed to what the gateway actually uses.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// OIDC Relying Party client. Cheap to clone; shares the inner cache.
#[derive(Clone)]
pub struct OidcClient {
    config: Arc<AuthConfig>,
    http: reqwest::Client,
    discovery: Arc<RwLock<Option<DiscoveryDocument>>>,
    jwks: Arc<RwLock<Option<HashMap<String, DecodingKey>>>>,
}

impl OidcClient {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config: Arc::new(config),
            // The auth callback is the only place we follow redirects; the
            // token exchange must not redirect (security: SSRF guard).
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builds with default features"),
            discovery: Arc::new(RwLock::new(None)),
            jwks: Arc::new(RwLock::new(None)),
        }
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Build the IdP authorization URL the agent should send the user to.
    /// `state` and `nonce` are caller-supplied (the route hands them out and
    /// remembers them across the redirect).
    pub async fn authorize_url(&self, state: &str, nonce: &str) -> Result<Url, AuthError> {
        let discovery = self.discover().await?;
        let mut url = Url::parse(&discovery.authorization_endpoint).map_err(|_| AuthError::Discovery)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("nonce", nonce);
        Ok(url)
    }

    /// Exchange an authorization code for an ID token, verify it, and pluck
    /// the subject, email, and groups claim.
    pub async fn exchange_and_verify(
        &self,
        code: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        let discovery = self.discover().await?;

        let response = self
            .http
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.config.redirect_url),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send()
            .await
            .map_err(|_| AuthError::CodeExchange)?;

        if !response.status().is_success() {
            return Err(AuthError::CodeExchange);
        }
        let token: TokenResponse = response.json().await.map_err(|_| AuthError::CodeExchange)?;
        self.verify_id_token(&token.id_token, expected_nonce).await
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        let header = jsonwebtoken::decode_header(id_token).map_err(|_| AuthError::IdToken)?;
        let kid = header.kid.ok_or(AuthError::IdToken)?;
        let key = self.decoding_key(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;

        let data = jsonwebtoken::decode::<serde_json::Value>(id_token, &key, &validation)
            .map_err(|_| AuthError::IdToken)?;
        let claims = data.claims;

        let nonce = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        // Constant-time nonce check would be ideal; this string is short and
        // not secret-extractable via timing, so eq is fine here.
        if nonce != expected_nonce {
            return Err(AuthError::IdToken);
        }

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::IdToken)?
            .to_string();
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let groups = claims
            .get(self.config.groups_claim.as_str())
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|g| g.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Ok(VerifiedIdentity {
            sub,
            email,
            groups,
        })
    }

    async fn discover(&self) -> Result<DiscoveryDocument, AuthError> {
        if let Some(d) = self.discovery.read().await.as_ref() {
            return Ok(d.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let doc: DiscoveryDocument = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| AuthError::Discovery)?
            .error_for_status()
            .map_err(|_| AuthError::Discovery)?
            .json()
            .await
            .map_err(|_| AuthError::Discovery)?;

        // Issuer per OIDC §4: must match the one we asked for. Stops a tampered
        // discovery doc from quietly pointing us at a different IdP.
        if doc.issuer.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err(AuthError::Discovery);
        }

        *self.discovery.write().await = Some(doc.clone());
        Ok(doc)
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        if let Some(key) = self.jwks.read().await.as_ref().and_then(|m| m.get(kid).cloned()) {
            return Ok(key);
        }
        let discovery = self.discover().await?;
        let jwks: Jwks = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|_| AuthError::Discovery)?
            .error_for_status()
            .map_err(|_| AuthError::Discovery)?
            .json()
            .await
            .map_err(|_| AuthError::Discovery)?;

        let mut by_kid: HashMap<String, DecodingKey> = HashMap::new();
        for jwk in jwks.keys {
            let Some(jwk_kid) = jwk.kid.clone() else {
                continue;
            };
            if jwk.kty != "RSA" {
                continue;
            }
            if let Some(use_) = &jwk.use_
                && use_ != "sig"
            {
                continue;
            }
            let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
                continue;
            };
            if let Ok(key) = DecodingKey::from_rsa_components(n, e) {
                by_kid.insert(jwk_kid, key);
            }
        }
        let key = by_kid.get(kid).cloned().ok_or(AuthError::IdToken)?;
        *self.jwks.write().await = Some(by_kid);
        Ok(key)
    }
}

