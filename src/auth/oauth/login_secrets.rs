//! The two secrets a pending IdP login needs at `/auth/callback` — the ID
//! token `nonce` and the gateway's own PKCE `code_verifier` — derived from the
//! OIDC `state` under a key every replica shares, instead of being stored. So
//! the state DB row of a pending login (`oauth_pending_flows`) holds neither,
//! and the replica the IdP sends the browser back to recomputes both.
//!
//! The key is itself derived from the session signing key, which replicas must
//! already share for each other's bearers to verify. A verifier is only as
//! secret as that key: knowing `state` alone (it travels through the browser
//! and the IdP) yields nothing.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::pkce;

/// Domain-separates this key from every other use of the signing key.
const KEY_LABEL: &[u8] = b"db-mcp-gateway/oauth-login-flow/v1";

/// What `/auth/login` or `/authorize` sends the IdP for a login keyed by
/// `state`, and what `/auth/callback` checks the IdP's answer against.
pub struct LoginSecrets {
    pub nonce: String,
    /// 43 base64url characters: inside RFC 7636's verifier charset and length.
    pub idp_verifier: String,
}

impl LoginSecrets {
    /// The S256 challenge for [`Self::idp_verifier`].
    pub fn idp_challenge(&self) -> String {
        pkce::challenge_for(&self.idp_verifier)
    }
}

/// The per-deployment key the login secrets are derived under. `Debug`
/// (in `redaction`) never prints it.
#[derive(Clone)]
pub(super) struct FlowKey(Arc<[u8; 32]>);

impl FlowKey {
    /// The key every replica holding `signing_key` derives alike.
    pub(super) fn from_signing_key(signing_key: &[u8]) -> Self {
        Self(Arc::new(hmac_sha256(signing_key, &[KEY_LABEL])))
    }

    /// A key no other process holds: for the single-process memory store.
    pub(super) fn random() -> Self {
        let seed = [Uuid::new_v4().into_bytes(), Uuid::new_v4().into_bytes()].concat();
        Self(Arc::new(Sha256::digest(&seed).into()))
    }

    pub(super) fn secrets(&self, state: &str) -> LoginSecrets {
        LoginSecrets {
            nonce: self.derive(b"nonce", state),
            idp_verifier: self.derive(b"idp_verifier", state),
        }
    }

    fn derive(&self, purpose: &[u8], state: &str) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(
            self.0.as_slice(),
            &[purpose, b"\0", state.as_bytes()],
        ))
    }
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `message`, on the `sha2`
/// already in the graph rather than a new dependency for twelve lines.
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for part in message {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hex(&hmac_sha256(
                b"Jefe",
                &[b"what do ya ", b"want for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let long_key = [0xaa; 131];
        assert_eq!(
            hex(&hmac_sha256(
                &long_key,
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn replicas_sharing_a_signing_key_derive_the_same_secrets() {
        let a = FlowKey::from_signing_key(b"shared-signing-key").secrets("state-1");
        let b = FlowKey::from_signing_key(b"shared-signing-key").secrets("state-1");
        assert_eq!(a.nonce, b.nonce);
        assert_eq!(a.idp_verifier, b.idp_verifier);
        assert_eq!(a.idp_challenge(), b.idp_challenge());
    }

    #[test]
    fn secrets_differ_by_state_key_and_purpose() {
        let key = FlowKey::from_signing_key(b"k");
        let one = key.secrets("state-1");
        assert_ne!(one.nonce, one.idp_verifier);
        assert_ne!(one.idp_verifier, key.secrets("state-2").idp_verifier);
        let other = FlowKey::from_signing_key(b"other").secrets("state-1");
        assert_ne!(one.idp_verifier, other.idp_verifier);
        assert_ne!(
            one.idp_verifier,
            FlowKey::random().secrets("state-1").idp_verifier
        );
    }

    #[test]
    fn verifier_is_a_valid_rfc_7636_verifier() {
        let verifier = FlowKey::random().secrets("s").idp_verifier;
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
