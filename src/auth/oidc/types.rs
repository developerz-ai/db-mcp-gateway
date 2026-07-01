use std::collections::HashMap;
use std::time::Instant;

use jsonwebtoken::DecodingKey;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct Jwks {
    pub(super) keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Jwk {
    pub(super) kid: Option<String>,
    pub(super) kty: String,
    #[serde(rename = "use")]
    pub(super) use_: Option<String>,
    pub(super) n: Option<String>,
    pub(super) e: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenResponse {
    pub(super) id_token: String,
}

/// Verified ID-token payload, narrowed to what the gateway actually uses.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// JWKS with a fetched-at timestamp so we can rotate keys without a restart.
#[derive(Clone)]
pub(super) struct JwksCache {
    pub(super) keys: HashMap<String, DecodingKey>,
    pub(super) fetched_at: Instant,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `DecodingKey` from `jsonwebtoken` 9.x doesn't derive `Debug`. Print
        // the count and freshness instead — opaque key material never belongs
        // in a log line anyway.
        f.debug_struct("JwksCache")
            .field("keys", &self.keys.len())
            .field("fetched_at", &self.fetched_at)
            .finish()
    }
}
