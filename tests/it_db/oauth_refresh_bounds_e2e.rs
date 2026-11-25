//! What `/token` refuses on top of a bad grant, over HTTP against the real
//! state DB: a refresh whose login is older than `GROUPS_MAX_AGE` (the user
//! signs in again, so the IdP's current groups apply), and an RFC 8707
//! `resource` that is not this gateway (refused before the code is spent).

use db_mcp_gateway::auth::LoginOptions;
use db_mcp_gateway::auth::oauth::{DEFAULT_REFRESH_TTL, RefreshTokens};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::audit::assert_audit_outcome;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client};
use crate::common::idp::{MockUser, spawn_mock_idp};

// RFC 7636 Appendix B test vector.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_REDIRECT: &str = "http://127.0.0.1:54603/callback";
const YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: schema_read }
"#;

struct Gateway {
    url: String,
    sub: String,
    http: reqwest::Client,
}

/// A gateway with DB-backed refresh chains, `GROUPS_MAX_AGE=groups_max_age`.
async fn spawn(pool: &PgPool, groups_max_age: &str) -> Gateway {
    let sub = format!("groups-age-{}", Uuid::new_v4().simple());
    let user = MockUser {
        email: format!("{sub}@example.com"),
        sub: sub.clone(),
        groups: vec!["engineers".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let options = LoginOptions::from_lookup(|var| {
        (var == "GROUPS_MAX_AGE").then(|| groups_max_age.to_owned())
    })
    .expect("valid GROUPS_MAX_AGE");
    let gateway = GatewayBuilder::new(YAML)
        .idp(&idp)
        .refresh(RefreshTokens::with_db(pool.clone(), DEFAULT_REFRESH_TTL))
        .login_options(options)
        .spawn(pool.clone())
        .await;
    Gateway {
        url: gateway.url,
        sub,
        http: no_redirect_client(),
    }
}

fn location(response: &reqwest::Response) -> String {
    response.headers()["location"]
        .to_str()
        .expect("ascii Location")
        .to_owned()
}

impl Gateway {
    /// register → authorize → IdP → callback; the one-time code.
    async fn auth_code(&self) -> String {
        let registered: Value = self
            .http
            .post(format!("{}/register", self.url))
            .json(&json!({ "redirect_uris": [CLIENT_REDIRECT] }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let client_id = registered["client_id"].as_str().expect("client_id");
        let authorize = self
            .http
            .get(format!("{}/authorize", self.url))
            .query(&[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", CLIENT_REDIRECT),
                ("code_challenge", PKCE_CHALLENGE),
                ("code_challenge_method", "S256"),
                ("state", "s"),
            ])
            .send()
            .await
            .unwrap();
        let idp = self.http.get(location(&authorize)).send().await.unwrap();
        let callback = self.http.get(location(&idp)).send().await.unwrap();
        reqwest::Url::parse(&location(&callback))
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, code)| code.into_owned())
            .expect("code in the client redirect")
    }

    async fn token(&self, form: &[(&str, &str)]) -> (StatusCode, Value) {
        let response = self
            .http
            .post(format!("{}/token", self.url))
            .form(form)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }

    async fn redeem(&self, code: &str, resource: Option<&str>) -> (StatusCode, Value) {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ];
        form.extend(resource.map(|resource| ("resource", resource)));
        self.token(&form).await
    }

    async fn refresh(&self, refresh_token: &str) -> (StatusCode, Value) {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    async fn list_servers(&self, bearer: &str) -> StatusCode {
        self.http
            .post(format!("{}/mcp", self.url))
            .bearer_auth(bearer)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "list_servers"}}))
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Move the login behind every chain of this user `secs` into the past.
    async fn age_login(&self, pool: &PgPool, secs: f64) {
        sqlx::query(
            "UPDATE oauth_refresh_tokens \
             SET chain_issued_at = chain_issued_at - make_interval(secs => $2) \
             WHERE user_sub = $1",
        )
        .bind(&self.sub)
        .bind(secs)
        .execute(pool)
        .await
        .expect("age the chain");
    }
}

fn str_of<'a>(body: &'a Value, key: &str) -> &'a str {
    body[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {body}"))
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_refresh_past_groups_max_age_requires_a_new_login() {
    let pool = state_pool().await;
    let gw = spawn(&pool, "30m").await;
    let (status, pair) = gw.redeem(&gw.auth_code().await, None).await;
    assert_eq!(status, StatusCode::OK, "{pair}");
    assert_eq!(
        pair["expires_in"], 1800,
        "a session never outlives the bound"
    );
    let access = str_of(&pair, "access_token");
    assert_eq!(gw.list_servers(access).await, StatusCode::OK);
    assert_audit_outcome(&pool, &gw.sub, "list_servers", "success", "fresh login").await;

    // Half-way through the bound the refresh still works, cut to what is left.
    gw.age_login(&pool, 900.0).await;
    let (status, rotated) = gw.refresh(str_of(&pair, "refresh_token")).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let expires_in = rotated["expires_in"].as_u64().expect("expires_in");
    assert!((890..=900).contains(&expires_in), "{rotated}");

    gw.age_login(&pool, 900.0).await;
    let refresh_token = str_of(&rotated, "refresh_token");
    let (status, refused) = gw.refresh(refresh_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refused["error"], "invalid_grant", "{refused}");
    assert_eq!(refused["code"], "relogin_required", "{refused}");

    // Nothing of the old login survives: its bearer and its token are spent.
    let stale = str_of(&rotated, "access_token");
    assert_eq!(gw.list_servers(stale).await, StatusCode::UNAUTHORIZED);
    let (status, spent) = gw.refresh(refresh_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(spent["error"], "invalid_grant");
    assert!(spent.get("code").is_none(), "{spent}");

    // A new login reads the groups again and is audited as before.
    let (status, again) = gw.redeem(&gw.auth_code().await, None).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        gw.list_servers(str_of(&again, "access_token")).await,
        StatusCode::OK
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_calls WHERE user_sub = $1 AND tool = 'list_servers'",
    )
    .bind(&gw.sub)
    .fetch_one(&pool)
    .await
    .expect("audit count");
    assert_eq!(rows, 2, "the refused bearer reached no tool");
    delete_audit_calls(&pool, &gw.sub).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
// audit-guard: exempt — its one `tools/call` carries a revoked session and is refused 401 at the bearer check, before dispatch
async fn a_foreign_resource_is_invalid_target_and_spends_nothing() {
    let pool = state_pool().await;
    let gw = spawn(&pool, "1h").await;
    let code = gw.auth_code().await;
    let (status, refused) = gw
        .redeem(&code, Some("https://other.example.com/mcp"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refused["error"], "invalid_target", "{refused}");

    let ours = format!("{}/mcp", gw.url);
    let (status, pair) = gw.redeem(&code, Some(&ours)).await;
    assert_eq!(status, StatusCode::OK, "the code survived: {pair}");
    let refresh_token = str_of(&pair, "refresh_token");
    let foreign = gw
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("resource", "https://other.example.com/mcp"),
        ])
        .await;
    assert_eq!(foreign.1["error"], "invalid_target", "{}", foreign.1);
    let (status, _) = gw.refresh(refresh_token).await;
    assert_eq!(status, StatusCode::OK, "the refresh token survived");

    assert_eq!(
        gw.list_servers(str_of(&pair, "access_token")).await,
        StatusCode::UNAUTHORIZED,
        "rotation revoked the first session"
    );
    delete_audit_calls(&pool, &gw.sub).await;
}
