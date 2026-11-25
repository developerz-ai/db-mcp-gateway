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
use hmac::{Hmac, KeyInit, Mac};
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

/// HMAC-SHA256 (RFC 2104) over the concatenation of `message`.
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new(&block_key(key).into());
    for part in message {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// `key` as the one full block RFC 2104 makes of any key. `Hmac` would do it,
/// but only through `new_from_slice`, whose error no length of key can cause.
fn block_key(key: &[u8]) -> [u8; 64] {
    let mut block = [0; 64];
    match block.get_mut(..key.len()) {
        Some(head) => head.copy_from_slice(key),
        None => block[..32].copy_from_slice(&Sha256::digest(key)),
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 4231 test cases 1, 2, 3, 4, 6 and 7 (5 is the truncated-tag case).
    #[test]
    fn hmac_matches_rfc_4231() {
        let cases: [(&[u8], &[u8], &str); 6] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                &std::array::from_fn::<u8, 25, _>(|i| i as u8 + 1),
                &[0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the HMAC \
                  algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, message, expected) in cases {
            assert_eq!(hex(&hmac_sha256(key, &[message])), expected);
            let (head, tail) = message.split_at(message.len() / 2);
            assert_eq!(hex(&hmac_sha256(key, &[head, tail])), expected);
        }
    }

    /// The two sides of the key-hashing threshold: 64 bytes is used as is.
    #[test]
    fn hmac_key_is_hashed_only_past_one_block() {
        assert_eq!(
            hex(&hmac_sha256(&[b'k'; 64], &[b"x"])),
            "f91c4c403625fb06910ef93999265bbd2d62baeaec6ff36455498cc124fe3e66"
        );
        assert_eq!(
            hex(&hmac_sha256(&[b'k'; 65], &[b"x"])),
            "75092ca3ee2b307470c227697b42b3e65376aa3bae98fb5a1f7b7536daa9588a"
        );
    }

    /// Fixed outputs, computed with another HMAC implementation: a login
    /// started before a rolling deploy must finish on a replica after it.
    #[test]
    fn derived_secrets_are_pinned() {
        let short = FlowKey::from_signing_key(b"shared-signing-key").secrets("state-1");
        assert_eq!(short.nonce, "ZEXXGuYYocLh_YlLBg54XCdxHsKRSgADGtpj61appXg");
        assert_eq!(
            short.idp_verifier,
            "vWp4lAMx0RYmTJ6WnuayJalHlJr949eIVrQZJQ59JPc"
        );
        let long = FlowKey::from_signing_key(&[b'a'; 100]).secrets("state-1");
        assert_eq!(long.nonce, "I_W9AHsNBCO94hDNbvO29Qi3EzbYykChK1PrO8z5RxU");
        assert_eq!(
            long.idp_verifier,
            "3sHGHbaq07z-D0waOzKbEJ_npILFB08b-LaZTeCRBwg"
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
