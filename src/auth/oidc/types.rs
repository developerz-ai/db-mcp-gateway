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
    pub(super) alg: Option<String>,
    /// RSA modulus / exponent.
    pub(super) n: Option<String>,
    pub(super) e: Option<String>,
    /// EC curve and point.
    pub(super) crv: Option<String>,
    pub(super) x: Option<String>,
    pub(super) y: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenResponse {
    pub(super) id_token: String,
}

/// Verified ID-token payload, narrowed to what the gateway actually uses.
/// Built only by `OidcClient`, which refuses the reserved service prefix in
/// `sub`; `non_exhaustive` keeps other crates from building one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}
