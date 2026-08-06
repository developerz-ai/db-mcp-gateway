//! PKCE (RFC 7636) S256 helpers, shared by the two PKCE layers in this gateway:
//!
//! - **MCP client → gateway**: the gateway acts as the OAuth *authorization
//!   server*; `transport::oauth` verifies the client's `code_verifier` against
//!   the stored `code_challenge` at `/token`.
//! - **gateway → upstream IdP**: the gateway acts as an OAuth *client*;
//!   `auth::oidc` generates a verifier/challenge pair and proves possession at
//!   the IdP's token endpoint. Required because IdPs increasingly mandate PKCE
//!   for every client (e.g. equipo's `/authorize` rejects any request without
//!   `code_challenge_method=S256`).
//!
//! `challenge = base64url-no-pad(SHA256(verifier))`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Derive the S256 code challenge for a verifier.
pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Generate a `(verifier, challenge)` pair. The verifier is 64 hex chars (two
/// UUIDv4 worth of CSPRNG entropy) — well within RFC 7636's 43–128 unreserved
/// charset and length bounds.
pub fn generate() -> (String, String) {
    let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let challenge = challenge_for(&verifier);
    (verifier, challenge)
}

/// Constant-time S256 verification: `base64url-no-pad(SHA256(verifier)) ==
/// challenge`. Constant-time so a mismatch can't be probed byte-by-byte.
pub fn verify(verifier: &str, challenge: &str) -> bool {
    ct_eq(challenge_for(verifier).as_bytes(), challenge.as_bytes())
}

/// Constant-time byte comparison, shared with `service_token` (bearer-token
/// match). Constant-time so a mismatch can't be probed byte-by-byte.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(challenge_for(verifier), challenge);
        assert!(verify(verifier, challenge));
        assert!(!verify("wrong", challenge));
    }

    #[test]
    fn generated_pair_round_trips() {
        let (verifier, challenge) = generate();
        assert!(verifier.len() >= 43 && verifier.len() <= 128);
        assert!(verify(&verifier, &challenge));
    }
}
