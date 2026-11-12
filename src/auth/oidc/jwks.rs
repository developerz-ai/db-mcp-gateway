//! The IdP's signing keys, cached by `kid` with the algorithms each may verify.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey};

use super::types::{Jwk, Jwks};

/// JWKS cache lifetime. Keeps the IdP load low while bounding rotation lag.
pub(super) const JWKS_TTL: Duration = Duration::from_secs(3600);

/// An unknown `kid` refetches the JWKS (key rotation) at most this often, so a
/// stream of tokens naming a bogus `kid` can't turn into a stream of IdP GETs.
pub(super) const UNKNOWN_KID_REFETCH: Duration = Duration::from_secs(60);

/// Signature algorithms an ID token may use. Pinned: `none` and the HMAC
/// family are never accepted (A5), whatever the token header claims.
const ACCEPTED: [Algorithm; 3] = [Algorithm::RS256, Algorithm::PS256, Algorithm::ES256];

#[derive(Clone)]
pub(super) struct VerifyKey {
    key: DecodingKey,
    algorithms: Vec<Algorithm>,
}

impl VerifyKey {
    /// The decoding key, if this key may verify a token signed with `alg`.
    pub(super) fn for_alg(&self, alg: Algorithm) -> Option<&DecodingKey> {
        self.algorithms.contains(&alg).then_some(&self.key)
    }
}

/// JWKS with a fetched-at timestamp so we can rotate keys without a restart.
pub(super) struct JwksCache {
    keys: HashMap<String, VerifyKey>,
    fetched_at: Instant,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `DecodingKey` doesn't implement `Debug`; key material never belongs
        // in a log line anyway.
        f.debug_struct("JwksCache")
            .field("keys", &self.keys.len())
            .field("fetched_at", &self.fetched_at)
            .finish()
    }
}

/// What a cache read tells the caller to do for one `kid`.
pub(super) enum Probe {
    Hit(VerifyKey),
    /// Absent or stale: fetch.
    Fetch,
    /// Fetched moments ago and still unknown: reject without fetching.
    Unknown,
}

impl JwksCache {
    pub(super) fn new(jwks: Jwks) -> Self {
        Self {
            keys: jwks
                .keys
                .into_iter()
                .filter_map(|jwk| Some((jwk.kid.clone()?, verify_key(&jwk)?)))
                .collect(),
            fetched_at: Instant::now(),
        }
    }

    pub(super) fn get(&self, kid: &str) -> Option<VerifyKey> {
        self.keys.get(kid).cloned()
    }
}

pub(super) fn probe(cache: Option<&JwksCache>, kid: &str) -> Probe {
    let Some(cache) = cache else {
        return Probe::Fetch;
    };
    classify(cache.get(kid), cache.fetched_at.elapsed())
}

fn classify(key: Option<VerifyKey>, age: Duration) -> Probe {
    match key {
        Some(key) if age < JWKS_TTL => Probe::Hit(key),
        None if age < UNKNOWN_KID_REFETCH => Probe::Unknown,
        _ => Probe::Fetch,
    }
}

/// A signing key we can use, or `None` to skip it: wrong `use`, unsupported
/// type/curve, or a declared `alg` outside [`ACCEPTED`].
fn verify_key(jwk: &Jwk) -> Option<VerifyKey> {
    if jwk.use_.as_deref().is_some_and(|use_| use_ != "sig") {
        return None;
    }
    let (key, family) = match jwk.kty.as_str() {
        "RSA" => (
            DecodingKey::from_rsa_components(jwk.n.as_deref()?, jwk.e.as_deref()?).ok()?,
            vec![Algorithm::RS256, Algorithm::PS256],
        ),
        "EC" if jwk.crv.as_deref() == Some("P-256") => (
            DecodingKey::from_ec_components(jwk.x.as_deref()?, jwk.y.as_deref()?).ok()?,
            vec![Algorithm::ES256],
        ),
        _ => return None,
    };
    // A JWK that names its `alg` may verify only that one (RFC 7517 §4.4).
    let algorithms = match jwk.alg.as_deref() {
        None => family,
        Some(declared) => {
            let declared = declared.parse::<Algorithm>().ok()?;
            family.contains(&declared).then(|| vec![declared])?
        }
    };
    algorithms
        .iter()
        .all(|alg| ACCEPTED.contains(alg))
        .then_some(VerifyKey { key, algorithms })
}

#[cfg(test)]
#[path = "jwks_tests.rs"]
mod tests;
