//! Two gateway replicas on one state DB, no sticky routing (spec 02 §HA): each
//! leg of an MCP OAuth-bridge login lands on whichever replica the load
//! balancer picks, and the login still completes — `/authorize` on A, the IdP
//! callback on B, the consent POST on A, `/token` on B — with the resulting
//! bearer audited on both. Also: two replicas racing to redeem one code mint
//! exactly one grant.
//!
//! Both replicas share the IdP redirect URL (the load balancer's, here A's
//! address) and the session signing key, as a real deployment does; the test
//! plays the load balancer by sending the IdP's redirect to B.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use db_mcp_gateway::auth::jwt::SessionJwt;
use db_mcp_gateway::auth::oauth::{
    AuthCodes, AuthFacade, ClientRegistry, PendingFlows, RefreshTokens,
};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, ServiceTokenStore, SessionStore};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport::{self, AppState};
use reqwest::{StatusCode, Url};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

use super::oauth_consent::{CONFIG_YAML, hidden_field, query_param};
use crate::common::audit::assert_audit_outcome;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use crate::common::gateway::{bind, config_file, no_redirect_client, serve};
use crate::common::idp::{MockIdpHandle, MockUser, spawn_mock_idp};

// RFC 7636 Appendix B test vector.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const HTTPS_REDIRECT: &str = "https://app.example/cb";
const LOOPBACK_REDIRECT: &str = "http://127.0.0.1:54612/callback";

/// Serve one replica on `listener` with every login store in the state DB.
/// `idp_redirect` is the shared OIDC redirect URL.
fn spawn_replica(pool: &PgPool, idp: &MockIdpHandle, listener: TcpListener, idp_redirect: &str) {
    let addr = listener.local_addr().expect("listener address");
    let auth_config = AuthConfig {
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        client_secret: idp.client_secret.clone().into(),
        audience: idp.client_id.clone(),
        redirect_url: idp_redirect.to_string(),
        ..AuthConfig::default()
    };
    let config = config_file(CONFIG_YAML);
    let tokens = ServiceTokenStore::from_config(&config.service_accounts).expect("tokens");
    let auth = AuthFacade {
        jwt: SessionJwt::new(&auth_config.session_signing_key),
        flows: PendingFlows::with_db(pool.clone(), &auth_config.session_signing_key),
        codes: AuthCodes::with_db(pool.clone()),
        refresh: RefreshTokens::with_db(pool.clone(), Duration::from_secs(3600)),
        config: Arc::new(auth_config.clone()),
        sessions: SessionStore::new(pool.clone()),
        oidc: OidcClient::new(auth_config).expect("oidc client"),
        service_tokens: Arc::new(ArcSwap::from_pointee(tokens)),
    };
    let mut state = AppState::for_tests(config, pool.clone(), auth);
    state.oauth.client_registry = ClientRegistry::with_db(pool.clone());
    let config = Config {
        bind: addr,
        ..Config::default()
    };
    serve(
        listener,
        transport::router(&config, state).expect("router builds"),
    );
}

struct Pair {
    a: String,
    b: String,
    sub: String,
    pool: PgPool,
    http: reqwest::Client,
}

async fn spawn_pair() -> Pair {
    let pool = state_pool().await;
    let sub = format!("ha-user-{}", Uuid::new_v4().simple());
    let user = MockUser {
        email: format!("{sub}@example.com"),
        sub: sub.clone(),
        groups: vec!["engineers".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let ((listener_a, addr_a), (listener_b, addr_b)) = (bind().await, bind().await);
    let (a, b) = (format!("http://{addr_a}"), format!("http://{addr_b}"));
    let idp_redirect = format!("{a}/auth/callback");
    spawn_replica(&pool, &idp, listener_a, &idp_redirect);
    spawn_replica(&pool, &idp, listener_b, &idp_redirect);
    Pair {
        a,
        b,
        sub,
        pool,
        http: no_redirect_client(),
    }
}

fn location(resp: &reqwest::Response) -> String {
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    resp.headers()["location"].to_str().unwrap().to_string()
}

/// `url` with its scheme, host and port replaced by `base`'s.
fn on_replica(url: &str, base: &str) -> String {
    let url = Url::parse(url).unwrap();
    let path = &url[url::Position::BeforePath..];
    format!("{base}{path}")
}

impl Pair {
    async fn register(&self, base: &str, redirect: &str) -> String {
        let body: Value = self
            .http
            .post(format!("{base}/register"))
            .json(&json!({ "redirect_uris": [redirect] }))
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

    /// `/authorize` on `start`, the IdP leg, and the IdP's redirect delivered
    /// to `callback`; returns the callback's response.
    async fn login(
        &self,
        start: &str,
        callback: &str,
        client_id: &str,
        redirect: &str,
    ) -> reqwest::Response {
        let authorize = self
            .http
            .get(format!("{start}/authorize"))
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
        let idp = self.http.get(location(&authorize)).send().await.unwrap();
        let idp_redirect = location(&idp);
        self.http
            .get(on_replica(&idp_redirect, callback))
            .send()
            .await
            .unwrap()
    }

    async fn redeem(&self, base: &str, code: &str, redirect: &str) -> reqwest::Response {
        self.http
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect),
                ("code_verifier", PKCE_VERIFIER),
            ])
            .send()
            .await
            .unwrap()
    }

    async fn list_servers(&self, base: &str, bearer: &str) -> StatusCode {
        self.http
            .post(format!("{base}/mcp"))
            .bearer_auth(bearer)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "list_servers"}}))
            .send()
            .await
            .unwrap()
            .status()
    }

    async fn cleanup(&self, client_id: &str) {
        delete_audit_calls(&self.pool, &self.sub).await;
        sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .expect("cleanup client");
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_consented_login_completes_across_two_replicas() {
    let pair = spawn_pair().await;
    let client_id = pair.register(&pair.b, HTTPS_REDIRECT).await;

    let page = pair
        .login(&pair.a, &pair.b, &client_id, HTTPS_REDIRECT)
        .await;
    assert_eq!(
        page.status(),
        StatusCode::OK,
        "B rendered A's login's consent"
    );
    let page = page.text().await.unwrap();
    let approved = pair
        .http
        .post(format!("{}/authorize/consent", pair.a))
        .form(&[
            ("consent_id", hidden_field(&page, "consent_id").as_str()),
            ("csrf", hidden_field(&page, "csrf").as_str()),
            ("decision", "approve"),
        ])
        .send()
        .await
        .unwrap();
    let back = location(&approved);
    assert!(back.starts_with(HTTPS_REDIRECT), "{back}");
    assert_eq!(query_param(&back, "state").as_deref(), Some("client-state"));
    let code = query_param(&back, "code").expect("A released B's consent's code");

    let token = pair.redeem(&pair.b, &code, HTTPS_REDIRECT).await;
    assert_eq!(token.status(), StatusCode::OK);
    let token: Value = token.json().await.unwrap();
    let bearer = token["access_token"].as_str().expect("access token");

    for replica in [&pair.a, &pair.b] {
        assert_eq!(pair.list_servers(replica, bearer).await, StatusCode::OK);
        assert_audit_outcome(&pair.pool, &pair.sub, "list_servers", "success", replica).await;
    }
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_calls WHERE user_sub = $1 AND tool = 'list_servers'",
    )
    .bind(&pair.sub)
    .fetch_one(&pair.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2, "one audit row per replica's call");
    let replay = pair.redeem(&pair.a, &code, HTTPS_REDIRECT).await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "single-use across replicas"
    );
    pair.cleanup(&client_id).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn racing_redemptions_on_two_replicas_mint_one_grant() {
    let pair = spawn_pair().await;
    let client_id = pair.register(&pair.a, LOOPBACK_REDIRECT).await;
    let callback = pair
        .login(&pair.b, &pair.a, &client_id, LOOPBACK_REDIRECT)
        .await;
    let code = query_param(&location(&callback), "code").expect("loopback gets a code");

    let (on_a, on_b) = tokio::join!(
        pair.redeem(&pair.a, &code, LOOPBACK_REDIRECT),
        pair.redeem(&pair.b, &code, LOOPBACK_REDIRECT),
    );
    let mut statuses = [on_a.status(), on_b.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_REQUEST]);
    let chains: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_refresh_tokens WHERE user_sub = $1")
            .bind(&pair.sub)
            .fetch_one(&pair.pool)
            .await
            .unwrap();
    assert_eq!(chains, 1, "exactly one grant for one code");
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(&pair.sub)
        .execute(&pair.pool)
        .await
        .unwrap();
    pair.cleanup(&client_id).await;
}
