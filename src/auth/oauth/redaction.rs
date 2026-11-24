//! `Debug` for everything the login stores hold. `AuthFacade` derives `Debug`
//! and reaches all of it, so one stray `{:?}` would otherwise print pending
//! CSRF states, PKCE verifiers and the identities waiting on a code.

use std::fmt::{Debug, Formatter, Result};

use super::pending_flows::PendingConsent;
use super::{AuthCode, AuthCodes, GrantIdentity, OAuthBridge, PendingFlow, PendingFlows};

const REDACTED: &str = "<redacted>";

/// Subject, email and group names are personal data and IdP-controlled text.
impl Debug for GrantIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("GrantIdentity")
            .field("groups", &self.groups.len())
            .finish_non_exhaustive()
    }
}

impl Debug for OAuthBridge {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("OAuthBridge")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("client_redirect_uri", &self.client_redirect_uri)
            .field("client_state", &REDACTED)
            .field("code_challenge", &REDACTED)
            .field("resource", &self.resource)
            .finish()
    }
}

impl Debug for PendingFlow {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("PendingFlow")
            .field("nonce", &REDACTED)
            .field("idp_verifier", &REDACTED)
            .field("bridge", &self.bridge)
            .finish_non_exhaustive()
    }
}

impl Debug for PendingConsent {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("PendingConsent")
            .field("identity", &self.identity)
            .field("bridge", &self.bridge)
            .field("csrf", &REDACTED)
            .finish_non_exhaustive()
    }
}

/// The maps are keyed by the OIDC `state` and the consent id, both bearer
/// values for the flow they name; nothing inside is worth a log line.
impl Debug for PendingFlows {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("PendingFlows").finish_non_exhaustive()
    }
}

impl Debug for AuthCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("AuthCode")
            .field("identity", &self.identity)
            .field("code_challenge", &REDACTED)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Debug for AuthCodes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("AuthCodes").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRETS: [&str; 9] = [
        "sub-4711",
        "dana@example.com",
        "db-oncall",
        "client-state-secret",
        "challenge-secret",
        "nonce-secret",
        "verifier-secret",
        "csrf-secret",
        "oidc-state-secret",
    ];

    fn assert_redacted(printed: &str) {
        for secret in SECRETS {
            assert!(!printed.contains(secret), "`{secret}` in {printed}");
        }
    }

    fn identity() -> GrantIdentity {
        GrantIdentity {
            sub: "sub-4711".into(),
            email: "dana@example.com".into(),
            groups: vec!["db-oncall".into()],
        }
    }

    fn bridge() -> OAuthBridge {
        OAuthBridge {
            client_id: "mcp-client".into(),
            client_name: None,
            client_redirect_uri: "https://app.example/cb".into(),
            client_state: "client-state-secret".into(),
            code_challenge: "challenge-secret".into(),
            resource: None,
        }
    }

    #[test]
    fn identity_prints_only_its_group_count() {
        let printed = format!("{:?}", identity());
        assert_redacted(&printed);
        assert!(printed.contains("groups: 1"), "{printed}");
    }

    #[tokio::test]
    async fn pending_flows_and_consents_print_no_secret() {
        let flows = PendingFlows::default();
        flows
            .insert_bridge(
                "oidc-state-secret".into(),
                "nonce-secret".into(),
                "verifier-secret".into(),
                bridge(),
            )
            .await;
        flows
            .insert_consent(
                "consent-id".into(),
                "csrf-secret".into(),
                identity(),
                bridge(),
            )
            .await;
        assert_redacted(&format!("{flows:?}"));

        let flow = flows.take("oidc-state-secret").await.expect("live flow");
        let printed = format!("{flow:?}");
        assert_redacted(&printed);
        assert!(printed.contains("mcp-client"), "{printed}");

        let consent = flows
            .take_consent("consent-id")
            .await
            .expect("live consent");
        assert_redacted(&format!("{consent:?}"));
    }

    #[tokio::test]
    async fn auth_codes_print_no_secret() {
        let codes = AuthCodes::default();
        codes
            .insert(
                "code-secret",
                identity(),
                "challenge-secret".into(),
                "https://app.example/cb".into(),
                "mcp-client".into(),
            )
            .await
            .expect("stored");
        let printed = format!("{codes:?}");
        assert_redacted(&printed);
        assert!(!printed.contains("code-secret"), "{printed}");

        let code = codes.take("code-secret").await.expect("live code");
        assert_redacted(&format!("{code:?}"));
    }
}
