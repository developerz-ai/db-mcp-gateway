//! Minimal OIDC Relying Party.
//!
//! Hand-rolled to keep the auth surface readable for review. We lean on
//! `jsonwebtoken` for the crypto (signature, alg, exp) — the historically
//! risky bits — and validate `iss` / `aud` / `nonce` / `kid` ourselves.

mod helpers;
mod types;

use helpers::*;
use types::*;

pub use types::{DiscoveryDocument, VerifiedIdentity};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tokio::sync::RwLock;

use super::config::AuthConfig;
use super::errors::AuthError;

/// OIDC Relying Party client. Cheap to clone; shares the inner cache.
#[derive(Clone, Debug)]
pub struct OidcClient {
    config: Arc<AuthConfig>,
    http: reqwest::Client,
    discovery: Arc<RwLock<Option<DiscoveryDocument>>>,
    jwks: Arc<RwLock<Option<JwksCache>>>,
}

/// Cap on an IdP metadata round-trip (discovery, JWKS). These are small,
/// cacheable GETs against static documents; if one is slow, something is wrong
/// and failing fast is right.
const DEFAULT_IDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Cap on the authorization-code exchange specifically. Deliberately looser than
/// [`DEFAULT_IDP_TIMEOUT`]: this POST makes the IdP mint tokens, which means
/// touching its user store, and a busy IdP has been observed answering in
/// 3–27 s. At 10 s the gateway aborted a call the IdP then completed
/// successfully — the user got a bare `access_denied` at their loopback
/// callback while the IdP logged a 200, and a retry seconds later worked. A
/// browser login leg can afford to wait; a spurious sign-out failure can't.
/// Still bounded, so a genuinely hung IdP can't pin the task open (T3).
const TOKEN_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

impl OidcClient {
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        // Token exchange must not follow redirects (SSRF guard). Fall back to
        // `Client::new()` is NOT acceptable — that uses the default redirect
        // policy (up to 10 hops in reqwest 0.12) and would silently re-open
        // the very SSRF surface this client is supposed to close.
        // Bound every IdP round-trip so a hung/slow IdP can't pin a request
        // task open indefinitely (T3). connect_timeout caps the TCP/TLS dial;
        // timeout caps the whole request. The code exchange overrides the
        // latter — see `TOKEN_EXCHANGE_TIMEOUT`.
        use std::time::Duration;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEFAULT_IDP_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| AuthError::HttpClient)?;
        Ok(Self {
            config: Arc::new(config),
            http,
            discovery: Arc::new(RwLock::new(None)),
            jwks: Arc::new(RwLock::new(None)),
        })
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Build the IdP authorization URL the agent should send the user to.
    /// `state` and `nonce` are caller-supplied (the route hands them out and
    /// remembers them across the redirect).
    pub async fn authorize_url(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Result<url::Url, AuthError> {
        let discovery = self.discover().await?;
        let mut url =
            url::Url::parse(&discovery.authorization_endpoint).map_err(|_| AuthError::Discovery)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    /// Exchange an authorization code for an ID token, verify it, and pluck
    /// the subject, email, and groups claim. `code_verifier` proves the PKCE
    /// challenge sent at `authorize_url` (RFC 7636) — IdPs that mandate PKCE
    /// reject the exchange without it.
    pub async fn exchange_and_verify(
        &self,
        code: &str,
        expected_nonce: &str,
        code_verifier: &str,
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
                ("code_verifier", code_verifier),
            ])
            .timeout(TOKEN_EXCHANGE_TIMEOUT)
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

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;
        // `jsonwebtoken` leaves `nbf` off by default; without this a future-dated
        // ID token (not-yet-valid) would be accepted.
        validation.validate_nbf = true;

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
        // Email is the audit/admin identity: persisted to `permissions_users`
        // and stamped on every audit row. Many IdPs let a user set an arbitrary
        // address that stays `email_verified: false`, so trusting an unverified
        // value would feed a spoofable identity into the audit trail (A6).
        // Require the claim present AND `email_verified == true` before minting
        // an identity from it.
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(AuthError::EmailUnverified)?
            .to_string();
        if !claim_is_true(claims.get("email_verified")) {
            return Err(AuthError::EmailUnverified);
        }
        let groups = claims
            .get(self.config.groups_claim.as_str())
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|g| g.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Ok(VerifiedIdentity { sub, email, groups })
    }

    async fn discover(&self) -> Result<DiscoveryDocument, AuthError> {
        if let Some(d) = self.discovery.read().await.as_ref() {
            return Ok(d.clone());
        }
        // The configured issuer must be https (else discovery, code exchange,
        // and client_secret travel in plaintext — A4). Loopback http is allowed
        // for local dev / mock IdPs.
        require_secure_url(&self.config.issuer)?;
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

        // A discovery doc can repoint us at http endpoints even when the issuer
        // is https; reject any non-https (non-loopback) endpoint before we ever
        // POST the code + client_secret to it (A4).
        require_secure_url(&doc.authorization_endpoint)?;
        require_secure_url(&doc.token_endpoint)?;
        require_secure_url(&doc.jwks_uri)?;

        *self.discovery.write().await = Some(doc.clone());
        Ok(doc)
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Fast path: live cache that hasn't aged out.
        if let Some(key) = self.jwks.read().await.as_ref().and_then(|cache| {
            (cache.fetched_at.elapsed() < JWKS_TTL)
                .then(|| cache.keys.get(kid).cloned())
                .flatten()
        }) {
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
        // Write cache before lookup to prevent refetch amplification when a key is
        // unknown: subsequent requests for the same unknown kid use the cached JWKS set.
        *self.jwks.write().await = Some(JwksCache {
            keys: by_kid.clone(),
            fetched_at: Instant::now(),
        });
        let key = by_kid.get(kid).cloned().ok_or(AuthError::IdToken)?;
        Ok(key)
    }
}
