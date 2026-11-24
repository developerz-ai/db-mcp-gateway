//! ID-token verification: signature and registered claims through
//! `jsonwebtoken`, then the identity claims the gateway mints a session from.

use jsonwebtoken::Validation;

use super::helpers::claim_is_true;
use super::jwks::{self, JwksCache, Probe};
use super::{OidcClient, VerifiedIdentity, discovery::get_json, groups};
use crate::auth::errors::AuthError;
use crate::auth::session::is_service_subject;

impl OidcClient {
    pub(super) async fn verify_id_token(
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
        if is_service_subject(&sub) {
            // The subject itself stays out of the log: it is IdP-controlled.
            tracing::warn!(
                "ID token subject uses the reserved service-account prefix; login refused"
            );
            return Err(AuthError::IdToken);
        }
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
        let groups_claim = self.config.groups_claim.as_str();
        let groups = groups::from_claim(
            groups_claim,
            claims.get(groups_claim),
            self.options.groups_prefix.as_ref(),
        );

        Ok(VerifiedIdentity { sub, email, groups })
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
