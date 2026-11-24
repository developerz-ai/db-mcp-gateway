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

#[derive(Deserialize)]
pub(super) struct TokenResponse {
    pub(super) id_token: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse").finish_non_exhaustive()
    }
}

/// Verified ID-token payload, narrowed to what the gateway actually uses.
/// Built only by `OidcClient`, which refuses the reserved service prefix in
/// `sub`; `non_exhaustive` keeps other crates from building one. `Debug`
/// prints the group count only: subject, email and group names are personal
/// data and IdP-controlled text.
#[derive(Clone)]
#[non_exhaustive]
pub struct VerifiedIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

impl std::fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("groups", &self.groups.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_no_token_or_identity() {
        let token = TokenResponse {
            id_token: "eyJ-secret-id-token".into(),
        };
        assert!(!format!("{token:?}").contains("eyJ-secret-id-token"));

        let identity = VerifiedIdentity {
            sub: "sub-4711".into(),
            email: "dana@example.com".into(),
            groups: vec!["db-oncall".into()],
        };
        let printed = format!("{identity:?}");
        for hidden in ["sub-4711", "dana@example.com", "db-oncall"] {
            assert!(!printed.contains(hidden), "{printed}");
        }
        assert!(printed.contains("groups: 1"), "{printed}");
    }
}
