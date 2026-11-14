//! Confused-deputy guard: a dynamically registered client with a non-loopback
//! redirect gets no authorization code until the signed-in user approves it on
//! the gateway's consent page with a valid, single-use CSRF token. Loopback
//! redirects stay consent-free. Requires a running state Postgres (`bin/dev up`).

use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client};
use crate::common::idp::{MockUser, spawn_mock_idp};
use serde_json::{Value, json};

// RFC 7636 Appendix B test vector.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const HTTPS_REDIRECT: &str = "https://evil.example/cb";
const LOOPBACK_REDIRECT: &str = "http://127.0.0.1:54611/callback";

const CONFIG_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: consent test
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: schema_read }
"#;

struct Harness {
    gw: String,
    http: reqwest::Client,
}

async fn spawn() -> Harness {
    let user = MockUser {
        sub: format!("consent-user-{}", uuid::Uuid::new_v4().simple()),
        email: "victim@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let gw = GatewayBuilder::new(CONFIG_YAML)
        .idp(&idp)
        .spawn(state_pool().await)
        .await;
    Harness {
        gw: gw.url,
        http: no_redirect_client(),
    }
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("location")
        .expect("redirect sets Location")
        .to_str()
        .unwrap()
        .to_string()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Extract `value="…"` of the hidden input named `name` from the consent page.
fn hidden_field(page: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = page.find(&marker).expect("hidden field present") + marker.len();
    let len = page[start..].find('"').expect("closing quote");
    page[start..start + len].to_string()
}

impl Harness {
    async fn register(&self, redirect: &str) -> String {
        let body: Value = self
            .http
            .post(format!("{}/register", self.gw))
            .json(&json!({ "redirect_uris": [redirect], "client_name": "<b>Trusted</b>" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        body["client_id"].as_str().unwrap().to_string()
    }

    /// `/authorize` → mock IdP → `/auth/callback`; returns the callback response.
    async fn login(&self, client_id: &str, redirect: &str) -> reqwest::Response {
        let authorize = self
            .http
            .get(format!("{}/authorize", self.gw))
            .query(&[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect),
                ("code_challenge", PKCE_CHALLENGE),
                ("code_challenge_method", "S256"),
                ("state", "client-state"),
            ])
            .send()
            .await
            .unwrap();
        assert!(
            authorize.status().is_redirection(),
            "{}",
            authorize.status()
        );
        let idp = self.http.get(location(&authorize)).send().await.unwrap();
        assert!(idp.status().is_redirection());
        self.http.get(location(&idp)).send().await.unwrap()
    }

    async fn submit(&self, consent_id: &str, csrf: &str, decision: &str) -> reqwest::Response {
        self.http
            .post(format!("{}/authorize/consent", self.gw))
            .form(&[
                ("consent_id", consent_id),
                ("csrf", csrf),
                ("decision", decision),
            ])
            .send()
            .await
            .unwrap()
    }

    async fn redeem(&self, code: &str, redirect: &str) -> reqwest::StatusCode {
        self.http
            .post(format!("{}/token", self.gw))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect),
                ("code_verifier", PKCE_VERIFIER),
            ])
            .send()
            .await
            .unwrap()
            .status()
    }
}

/// The https flow stops at a consent page; a forged CSRF releases nothing and
/// burns the flow; a fresh flow with the rendered CSRF releases a working code;
/// replaying that approval is rejected.
#[tokio::test]
#[serial_test::parallel(world)]
async fn https_redirect_requires_consent_with_valid_csrf() {
    let h = spawn().await;
    let client_id = h.register(HTTPS_REDIRECT).await;

    let page_resp = h.login(&client_id, HTTPS_REDIRECT).await;
    assert_eq!(page_resp.status(), reqwest::StatusCode::OK);
    assert!(page_resp.headers().get("location").is_none(), "no code yet");
    let headers = page_resp.headers().clone();
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["cache-control"], "no-store");
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    let page = page_resp.text().await.unwrap();
    assert!(page.contains("class=\"host\">evil.example<"), "{page}");
    assert!(page.contains("victim@example.com"));
    assert!(
        !page.contains("<b>Trusted</b>"),
        "client markup never rendered"
    );

    // Forged CSRF: rejected without a redirect, and the flow is gone.
    let consent_id = hidden_field(&page, "consent_id");
    let csrf = hidden_field(&page, "csrf");
    let forged = h.submit(&consent_id, "not-the-token", "approve").await;
    assert_eq!(forged.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(forged.headers().get("location").is_none());
    let after = h.submit(&consent_id, &csrf, "approve").await;
    assert_eq!(after.status(), reqwest::StatusCode::BAD_REQUEST, "burned");

    // Fresh flow, genuine approval: code + state reach the redirect and redeem.
    let page = h
        .login(&client_id, HTTPS_REDIRECT)
        .await
        .text()
        .await
        .unwrap();
    let consent_id = hidden_field(&page, "consent_id");
    let csrf = hidden_field(&page, "csrf");
    let approved = h.submit(&consent_id, &csrf, "approve").await;
    assert!(approved.status().is_redirection(), "{}", approved.status());
    let back = location(&approved);
    assert!(back.starts_with(HTTPS_REDIRECT), "{back}");
    assert_eq!(query_param(&back, "state").as_deref(), Some("client-state"));
    let code = query_param(&back, "code").expect("code released on approve");
    assert_eq!(
        h.redeem(&code, HTTPS_REDIRECT).await,
        reqwest::StatusCode::OK
    );

    // Single-use CSRF: replaying the approval releases nothing.
    let replay = h.submit(&consent_id, &csrf, "approve").await;
    assert_eq!(replay.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(replay.headers().get("location").is_none());
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn deny_returns_access_denied_to_the_client() {
    let h = spawn().await;
    let client_id = h.register(HTTPS_REDIRECT).await;
    let page = h
        .login(&client_id, HTTPS_REDIRECT)
        .await
        .text()
        .await
        .unwrap();
    let denied = h
        .submit(
            &hidden_field(&page, "consent_id"),
            &hidden_field(&page, "csrf"),
            "deny",
        )
        .await;
    assert!(denied.status().is_redirection(), "{}", denied.status());
    let back = location(&denied);
    assert!(back.starts_with(HTTPS_REDIRECT), "{back}");
    assert_eq!(
        query_param(&back, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(query_param(&back, "state").as_deref(), Some("client-state"));
    assert_eq!(query_param(&back, "code"), None);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn loopback_redirect_skips_consent() {
    let h = spawn().await;
    let client_id = h.register(LOOPBACK_REDIRECT).await;
    let callback = h.login(&client_id, LOOPBACK_REDIRECT).await;
    assert!(callback.status().is_redirection(), "{}", callback.status());
    let back = location(&callback);
    assert!(back.starts_with(LOOPBACK_REDIRECT), "{back}");
    let code = query_param(&back, "code").expect("code issued directly");
    assert_eq!(
        h.redeem(&code, LOOPBACK_REDIRECT).await,
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn consent_rejects_unknown_fields_and_unknown_flows() {
    let h = spawn().await;
    let unknown = h.submit("no-such-flow", "x", "approve").await;
    assert_eq!(unknown.status(), reqwest::StatusCode::BAD_REQUEST);
    let extra = h
        .http
        .post(format!("{}/authorize/consent", h.gw))
        .form(&[
            ("consent_id", "a"),
            ("csrf", "b"),
            ("decision", "approve"),
            ("redirect_uri", "https://elsewhere.example/cb"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(extra.status(), reqwest::StatusCode::BAD_REQUEST);
}
