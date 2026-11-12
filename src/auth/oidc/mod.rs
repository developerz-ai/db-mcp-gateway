//! Minimal OIDC Relying Party.
//!
//! Hand-rolled to keep the auth surface readable for review. We lean on
//! `jsonwebtoken` for the crypto (signature, alg, exp) — the historically
//! risky bits — and validate `iss` / `aud` / `nonce` / `kid` ourselves.

mod discovery;
mod helpers;
mod jwks;
mod types;

use discovery::get_json;
use helpers::*;
use jwks::{JwksCache, Probe};
use types::*;

pub(crate) use helpers::is_loopback;
pub use types::{DiscoveryDocument, VerifiedIdentity};

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::Validation;
use tokio::sync::{Mutex, RwLock};

use super::config::AuthConfig;
use super::errors::AuthError;

/// OIDC Relying Party client. Cheap to clone; shares the inner cache.
#[derive(Clone, Debug)]
pub struct OidcClient {
    config: Arc<AuthConfig>,
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
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEFAULT_IDP_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| AuthError::HttpClient)?;
        Ok(Self {
            issuer: Arc::from(config.issuer.trim_end_matches('/')),
            config: Arc::new(config),
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
        // The JWKS decides which algorithms each key may verify; a header alg
        // outside that set (HS256, `none`, RSA-vs-EC confusion) never decodes.
        let verify_key = self.verify_key(&kid).await?;
        let key = verify_key.for_alg(header.alg).ok_or(AuthError::IdToken)?;
        // OIDC Core 3.1.3.7 step 2: `iss` must exactly match the discovery
        // document's issuer — compare against that, not the configured string,
        // so a trailing-slash difference in config can't reject valid tokens.
        let issuer = self.discover().await?.issuer;

        let mut validation = Validation::new(header.alg);
        // `set_issuer` / `set_audience` only constrain a claim that is *present*:
        // in `jsonwebtoken` 9.3 an absent `iss`/`aud` falls through the match to
        // `_ => {}`. `required_spec_claims` defaults to `{exp}` alone, and our
        // claims deserialize into `serde_json::Value`, so nothing else forces
        // them to exist — a token from the IdP's JWKS with no `aud` would verify.
        // Demanding them here is OIDC Core 3.1.3.7 step 3.
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[&issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;
        // `jsonwebtoken` leaves `nbf` off by default; without this a future-dated
        // ID token (not-yet-valid) would be accepted.
        validation.validate_nbf = true;

        let data = jsonwebtoken::decode::<serde_json::Value>(id_token, key, &validation)
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

    /// The key for `kid`. An unknown `kid` refetches the JWKS (the IdP rotated
    /// keys) at most once per [`jwks::UNKNOWN_KID_REFETCH`], and concurrent
    /// misses share one fetch.
    async fn verify_key(&self, kid: &str) -> Result<jwks::VerifyKey, AuthError> {
        if let Some(key) = self.probe_jwks(kid).await? {
            return Ok(key);
        }
        let _refresh = self.jwks_refresh.lock().await;
        if let Some(key) = self.probe_jwks(kid).await? {
            return Ok(key);
        }
        let discovery = self.discover().await?;
        let cache = JwksCache::new(get_json(&self.http, &discovery.jwks_uri).await?);
        let key = cache.get(kid);
        *self.jwks.write().await = Some(cache);
        key.ok_or(AuthError::IdToken)
    }

    /// `Ok(Some)` hit, `Ok(None)` fetch needed, `Err` known-unknown `kid`.
    async fn probe_jwks(&self, kid: &str) -> Result<Option<jwks::VerifyKey>, AuthError> {
        match jwks::probe(self.jwks.read().await.as_ref(), kid) {
            Probe::Hit(key) => Ok(Some(key)),
            Probe::Fetch => Ok(None),
            Probe::Unknown => Err(AuthError::IdToken),
        }
    }
}
