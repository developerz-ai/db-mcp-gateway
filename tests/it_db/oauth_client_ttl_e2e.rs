//! When a Dynamic-Client-Registration row earns its long lifetime, over HTTP
//! against the real state DB: `/authorize` is unauthenticated and must leave
//! the row on the short unused TTL (evictable at the cap); only a code
//! redeemed at `/token` — proof of a verified IdP login — promotes it.
//!
//! Also the one redemption `/token` must not offer again: a mint whose
//! COMMIT errored may have minted, so its code stays spent.
//!
//! The cap test is `#[serial_test::serial(world)]` (it fills the shared
//! `oauth_clients` table), as is the commit-failure test (it adds a trigger
//! to `oauth_refresh_tokens`); the rest touch only their own rows.

use db_mcp_gateway::auth::oauth::{AuthCodes, ClientRegistry, GrantIdentity, RefreshTokens};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::env::state_pool;
use crate::common::gateway::{EMPTY_YAML, GatewayBuilder, no_redirect_client};
use crate::common::idp::{MockUser, spawn_mock_idp};

// RFC 7636 Appendix B test vector.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_REDIRECT: &str = "http://127.0.0.1:54601/callback";

/// A gateway whose client registry is `registry` (the shared harness wires an
/// in-memory one), logging users in through a fresh mock IdP.
pub(crate) async fn spawn_gateway(pool: &PgPool, registry: ClientRegistry) -> String {
    let (codes, refresh) = (AuthCodes::default(), RefreshTokens::default());
    spawn_gateway_with(pool, registry, codes, refresh).await
}

/// [`spawn_gateway`] over the caller's code and refresh-token stores.
pub(crate) async fn spawn_gateway_with(
    pool: &PgPool,
    registry: ClientRegistry,
    codes: AuthCodes,
    refresh: RefreshTokens,
) -> String {
    let sub = format!("ttl-e2e-{}", Uuid::new_v4().simple());
    let user = MockUser {
        email: format!("{sub}@example.com"),
        sub,
        groups: vec!["engineers".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    GatewayBuilder::new(EMPTY_YAML)
        .idp(&idp)
        .registry(registry)
        .codes(codes)
        .refresh(refresh)
        .spawn(pool.clone())
        .await
        .url
}

async fn register(http: &reqwest::Client, gateway: &str) -> String {
    let body: Value = http
        .post(format!("{gateway}/register"))
        .json(&json!({ "redirect_uris": [CLIENT_REDIRECT] }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("registration succeeds")
        .json()
        .await
        .unwrap();
    body["client_id"].as_str().expect("client_id").to_string()
}

pub(crate) async fn authorize(
    http: &reqwest::Client,
    gateway: &str,
    client_id: &str,
) -> reqwest::Response {
    http.get(format!("{gateway}/authorize"))
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
        .unwrap()
}

fn location(resp: &reqwest::Response) -> String {
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    resp.headers()["location"].to_str().unwrap().to_string()
}

/// `Some(true)` while the row is still on the unused TTL (evictable at the
/// cap), `Some(false)` once promoted, `None` when there is no row.
async fn on_unused_ttl(pool: &PgPool, client_id: &str) -> Option<bool> {
    sqlx::query_scalar(
        "SELECT expires_at <= created_at + interval '1 hour' \
         FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .expect("read client row")
}

pub(crate) async fn cleanup(pool: &PgPool, client_id: &str) {
    sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(pool)
        .await
        .expect("cleanup");
}

/// Anyone can call `/authorize`; doing so — any number of times — must not
/// move a registration out of eviction range.
#[tokio::test]
#[serial_test::parallel(world)]
async fn authorize_without_a_login_leaves_the_client_on_the_unused_ttl() {
    let pool = state_pool().await;
    let gateway = spawn_gateway(&pool, ClientRegistry::with_db(pool.clone())).await;
    let http = no_redirect_client();
    let client_id = register(&http, &gateway).await;

    for _ in 0..5 {
        let resp = authorize(&http, &gateway, &client_id).await;
        assert!(resp.status().is_redirection(), "302 to the IdP");
    }
    assert_eq!(on_unused_ttl(&pool, &client_id).await, Some(true));

    cleanup(&pool, &client_id).await;
}

/// The full dance: the row stays unused through `/authorize` and the IdP
/// callback, and is promoted to the long TTL when the code is redeemed.
#[tokio::test]
#[serial_test::parallel(world)]
async fn redeeming_a_code_promotes_the_client_to_the_long_ttl() {
    let pool = state_pool().await;
    let gateway = spawn_gateway(&pool, ClientRegistry::with_db(pool.clone())).await;
    let http = no_redirect_client();
    let client_id = register(&http, &gateway).await;

    let to_idp = authorize(&http, &gateway, &client_id).await;
    let to_callback = http.get(location(&to_idp)).send().await.unwrap();
    let to_client = http.get(location(&to_callback)).send().await.unwrap();
    let client_redirect = reqwest::Url::parse(&location(&to_client)).unwrap();
    let code = client_redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("authorization code");
    assert_eq!(
        on_unused_ttl(&pool, &client_id).await,
        Some(true),
        "a code that was never redeemed promotes nothing"
    );

    let token = http
        .post(format!("{gateway}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
            ("client_id", client_id.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    assert_eq!(on_unused_ttl(&pool, &client_id).await, Some(false));
    let long_lived: bool = sqlx::query_scalar(
        "SELECT expires_at > now() + interval '89 days' FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&pool)
    .await
    .expect("read expiry");
    assert!(long_lived, "a used client carries the 90-day TTL");

    cleanup(&pool, &client_id).await;
}

/// An unknown `client_id` adopted on a loopback redirect is recorded, but as
/// unused: adoption is as unauthenticated as `/register`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn adopted_client_starts_on_the_unused_ttl() {
    let pool = state_pool().await;
    let gateway = spawn_gateway(&pool, ClientRegistry::with_db(pool.clone())).await;
    let http = no_redirect_client();
    let client_id = format!("adopted-{}", Uuid::new_v4().simple());

    let resp = authorize(&http, &gateway, &client_id).await;
    assert!(resp.status().is_redirection(), "adopted, 302 to the IdP");
    assert_eq!(on_unused_ttl(&pool, &client_id).await, Some(true));

    cleanup(&pool, &client_id).await;
}

/// The unauthenticated fill: every row of a registry at its cap is resolved
/// the way `/authorize` resolves it. None of them may leave eviction range,
/// so the next `/register` still finds room.
#[tokio::test]
#[serial_test::serial(world)]
async fn resolving_every_unused_client_does_not_block_registration() {
    let pool = state_pool().await;
    let prefix = format!("fill-{}-", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, created_at, expires_at) \
         SELECT $1 || g, jsonb_build_array($2::text), \
                now() - make_interval(secs => 3000 - g * 0.1), \
                now() - make_interval(secs => 3000 - g * 0.1) + interval '1 hour' \
         FROM generate_series(1, 10000) g",
    )
    .bind(&prefix)
    .bind(CLIENT_REDIRECT)
    .execute(&pool)
    .await
    .expect("seed to the cap");

    let registry = ClientRegistry::with_db(pool.clone());
    let gateway = spawn_gateway(&pool, registry.clone()).await;
    let http = no_redirect_client();
    // A sample through the real endpoint, the rest through the lookup it runs.
    for g in 1..=20 {
        let resp = authorize(&http, &gateway, &format!("{prefix}{g}")).await;
        assert!(resp.status().is_redirection(), "302 to the IdP");
    }
    for g in 21..=10_000 {
        let found = registry.lookup(&format!("{prefix}{g}")).await;
        assert!(matches!(found, Ok(Some(_))), "seeded client {g} resolves");
    }

    let registered = http
        .post(format!("{gateway}/register"))
        .json(&json!({ "redirect_uris": [CLIENT_REDIRECT] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        registered.status(),
        StatusCode::CREATED,
        "a registry full of never-used clients still admits a new one"
    );
    let body: Value = registered.json().await.unwrap();

    cleanup(&pool, body["client_id"].as_str().expect("client_id")).await;
    sqlx::query("DELETE FROM oauth_clients WHERE client_id LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await
        .expect("cleanup seeded rows");
}

/// Make every COMMIT that inserted a refresh token of `sub` fail: the
/// statements succeed, and the caller learns of the failure only from the
/// COMMIT's reply — all it ever knows of a commit whose reply was lost.
pub(crate) async fn fail_commits_minting_for(pool: &PgPool, trigger: &str, sub: &str) {
    for ddl in [
        format!(
            "CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'commit refused by test'; END $$"
        ),
        format!(
            "CREATE CONSTRAINT TRIGGER {trigger} AFTER INSERT ON oauth_refresh_tokens \
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.user_sub = '{sub}') \
             EXECUTE FUNCTION {trigger}()"
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(ddl))
            .execute(pool)
            .await
            .expect("install");
    }
}

/// `/token` cannot tell a COMMIT that failed from one whose reply was lost,
/// so after either it must not hand the code back: a retry would mint a
/// second grant for one authorization. The client is told to start over.
#[tokio::test]
#[serial_test::serial(world)]
async fn a_mint_whose_commit_errored_keeps_the_code_spent() {
    let pool = state_pool().await;
    let sub = format!("commit-lost-{}", Uuid::new_v4().simple());
    // The production code store: the spent code must stay spent in the table.
    let codes = AuthCodes::with_db(pool.clone());
    let refresh = RefreshTokens::with_db(pool.clone(), std::time::Duration::from_secs(3600));
    let gateway =
        spawn_gateway_with(&pool, ClientRegistry::default(), codes.clone(), refresh).await;
    let identity = GrantIdentity {
        sub: sub.clone(),
        email: format!("{sub}@example.com"),
        groups: vec!["engineers".into()],
    };
    let (challenge, redirect) = (PKCE_CHALLENGE.to_string(), CLIENT_REDIRECT.to_string());
    let code = format!("lost-commit-{}", Uuid::new_v4().simple());
    codes
        .insert(&code, identity, challenge, redirect, "c1".into())
        .await
        .expect("code stored");
    let trigger = format!("fail_commit_{}", Uuid::new_v4().simple());
    fail_commits_minting_for(&pool, &trigger, &sub).await;

    let resp = no_redirect_client()
        .post(format!("{gateway}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    let code_left = codes.take(&code).await.expect("state DB up");

    for ddl in [
        format!("DROP TRIGGER {trigger} ON oauth_refresh_tokens"),
        format!("DROP FUNCTION {trigger}()"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(ddl))
            .execute(&pool)
            .await
            .expect("uninstall");
    }
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    let description = body["error_description"].as_str().unwrap_or_default();
    assert!(description.contains("restart authorization"), "{body}");
    assert!(
        code_left.is_none(),
        "a mint that may have committed left its code redeemable"
    );
}
