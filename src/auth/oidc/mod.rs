//! Minimal OIDC Relying Party.
//!
//! Hand-rolled to keep the auth surface readable for review. We lean on
//! `jsonwebtoken` for the crypto (signature, alg, exp) — the historically
//! risky bits — and validate `iss` / `aud` / `nonce` / `kid` ourselves.

mod discovery;
mod groups;
mod helpers;
mod jwks;
mod options;
mod types;
mod verify;

use jwks::JwksCache;
use types::TokenResponse;

pub(crate) use helpers::is_loopback;
pub use options::{
    GroupsPrefix, LoginOptions, LoginOptionsError, Scopes, SupportContact, TokenAuthMethod,
};
pub use types::{DiscoveryDocument, VerifiedIdentity};

use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::ExposeSecret;
use tokio::sync::{Mutex, RwLock};

use super::config::AuthConfig;
use super::errors::AuthError;

/// OIDC Relying Party client. Cheap to clone; shares the inner cache.
#[derive(Clone, Debug)]
pub struct OidcClient {
    config: Arc<AuthConfig>,
    options: Arc<LoginOptions>,
    /// `config.issuer` without a trailing slash: the one form used to build
    /// the discovery URL and to compare against the discovery document.
    issuer: Arc<str>,
    http: reqwest::Client,
    discovery: Arc<RwLock<Option<(DiscoveryDocument, Instant)>>>,
    /// Serializes discovery refetches; holders re-check the cache first.
    discovery_refresh: Arc<Mutex<()>>,
    jwks: Arc<RwLock<Option<JwksCache>>>,
    /// Serializes JWKS refetches; holders re-check the cache first.
    jwks_refresh: Arc<Mutex<()>>,
}

/// Discovery is re-read this often, so an IdP that moves an endpoint or its
/// `jwks_uri` is picked up without a restart.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

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

/// Cap on everything `/auth/callback` waits on at the IdP for one login:
/// discovery, the code exchange and a JWKS fetch. Each has its own timeout
/// above, but back to back on cold caches they add up to 65 s — past the
/// router's deadline, which answers a bare `504` with no redirect back to the
/// client. `transport::bounds` sizes that deadline from this constant.
pub const LOGIN_IDP_BUDGET: Duration = Duration::from_secs(50);

impl OidcClient {
    /// A client with default [`LoginOptions`].
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        Self::with_options(config, LoginOptions::default())
    }

    pub fn with_options(config: AuthConfig, options: LoginOptions) -> Result<Self, AuthError> {
        // Token exchange must not follow redirects (SSRF guard). Fall back to
        // `Client::new()` is NOT acceptable — that uses the default redirect
        // policy (up to 10 hops in reqwest 0.12) and would silently re-open
        // the very SSRF surface this client is supposed to close.
        // Bound every IdP round-trip so a hung/slow IdP can't pin a request
        // task open indefinitely (T3). connect_timeout caps the TCP/TLS dial;
        // timeout caps the whole request. The code exchange overrides the
        // latter — see `TOKEN_EXCHANGE_TIMEOUT`.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEFAULT_IDP_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| AuthError::HttpClient)?;
        Ok(Self {
            issuer: Arc::from(config.issuer.trim_end_matches('/')),
            config: Arc::new(config),
            options: Arc::new(options),
            http,
            discovery: Arc::new(RwLock::new(None)),
            discovery_refresh: Arc::new(Mutex::new(())),
            jwks: Arc::new(RwLock::new(None)),
            jwks_refresh: Arc::new(Mutex::new(())),
        })
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    pub fn options(&self) -> &LoginOptions {
        &self.options
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
            .append_pair("scope", self.options.scopes.as_str())
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    /// Exchange an authorization code for an ID token, verify it, and pluck
    /// the subject, email, and groups claim. `code_verifier` proves the PKCE
    /// challenge sent at `authorize_url` (RFC 7636) — IdPs that mandate PKCE
    /// reject the exchange without it. Gives up after [`LOGIN_IDP_BUDGET`].
    pub async fn exchange_and_verify(
        &self,
        code: &str,
        expected_nonce: &str,
        code_verifier: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        let login = self.exchange_then_verify(code, expected_nonce, code_verifier);
        match tokio::time::timeout(LOGIN_IDP_BUDGET, login).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("IdP did not complete the login within the budget");
                Err(AuthError::CodeExchange)
            }
        }
    }

    async fn exchange_then_verify(
        &self,
        code: &str,
        expected_nonce: &str,
        code_verifier: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        let discovery = self.discover().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("code_verifier", code_verifier),
        ];
        let client_id = self.config.client_id.as_str();
        let client_secret = self.config.client_secret.expose_secret();
        let request = self.http.post(&discovery.token_endpoint);
        let request = match self.options.token_auth_method {
            TokenAuthMethod::ClientSecretPost => {
                form.extend([("client_id", client_id), ("client_secret", client_secret)]);
                request
            }
            // RFC 6749 §2.3.1: both halves are form-urlencoded before Basic
            // encoding, so a `:` or non-ASCII byte in either survives.
            TokenAuthMethod::ClientSecretBasic => request.basic_auth(
                form_urlencode(client_id),
                Some(form_urlencode(client_secret)),
            ),
        };
        let response = request
            .form(&form)
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

    async fn discover(&self) -> Result<DiscoveryDocument, AuthError> {
        if let Some(doc) = self.fresh_discovery().await {
            return Ok(doc);
        }
        let _refresh = self.discovery_refresh.lock().await;
        if let Some(doc) = self.fresh_discovery().await {
            return Ok(doc);
        }
        let doc = discovery::fetch(&self.http, &self.issuer).await?;
        *self.discovery.write().await = Some((doc.clone(), Instant::now()));
        Ok(doc)
    }

    async fn fresh_discovery(&self) -> Option<DiscoveryDocument> {
        self.discovery
            .read()
            .await
            .as_ref()
            .filter(|(_, fetched_at)| fetched_at.elapsed() < DISCOVERY_TTL)
            .map(|(doc, _)| doc.clone())
    }
}

fn form_urlencode(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_exchange_fits_inside_the_login_budget() {
        assert!(TOKEN_EXCHANGE_TIMEOUT <= LOGIN_IDP_BUDGET);
    }

    #[test]
    fn basic_credentials_are_form_urlencoded() {
        assert_eq!(form_urlencode("id:with space"), "id%3Awith+space");
        assert_eq!(form_urlencode("s3cr/t+é"), "s3cr%2Ft%2B%C3%A9");
    }
}
