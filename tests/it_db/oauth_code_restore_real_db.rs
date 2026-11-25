//! `/token`'s code-restore contract on the state-DB code store: a redemption
//! that failed provably before anything was issued puts the code back in
//! `oauth_auth_codes`, so the client's retry — on any replica — redeems it.
//! (A mint whose COMMIT errored keeps it spent:
//! `oauth_client_ttl_e2e::a_mint_whose_commit_errored_keeps_the_code_spent`.)
//!
//! A code from an old replica's in-memory store is `invalid_grant` on a new one.
//!
//! The mint-failure test is `#[serial_test::serial(world)]` (it adds a
//! trigger to `oauth_refresh_tokens`); the promotion test touches only its
//! own rows.

use std::time::Duration;

use db_mcp_gateway::auth::oauth::{AuthCodes, ClientRegistry, GrantIdentity, RefreshTokens};
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

use super::oauth_client_ttl_e2e::spawn_gateway_with;
use crate::common::env::state_pool;
use crate::common::gateway::no_redirect_client;

// RFC 7636 Appendix B test vector.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_REDIRECT: &str = "http://127.0.0.1:54601/callback";

/// A code for a fresh subject in the state DB; returns `(code, sub)`.
async fn seed_code(codes: &AuthCodes) -> (String, String) {
    let sub = format!("restore-{}", Uuid::new_v4().simple());
    let code = format!("restore-code-{}", Uuid::new_v4().simple());
    let identity = GrantIdentity {
        sub: sub.clone(),
        email: format!("{sub}@example.com"),
        groups: vec!["engineers".into()],
    };
    codes
        .insert(
            &code,
            identity,
            PKCE_CHALLENGE.into(),
            CLIENT_REDIRECT.into(),
            "c1".into(),
        )
        .await
        .expect("code stored");
    (code, sub)
}

async fn redeem(gateway: &str, code: &str) -> (StatusCode, Value) {
    let resp = no_redirect_client()
        .post(format!("{gateway}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();
    (resp.status(), resp.json().await.unwrap())
}

fn refresh(pool: &PgPool) -> RefreshTokens {
    RefreshTokens::with_db(pool.clone(), Duration::from_secs(3600))
}

/// The registry's state DB is down at promotion: the 503 says "try again", and
/// the retry, on another replica whose registry is up, finds the code.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_failed_promotion_puts_the_code_back_for_any_replica() {
    let pool = state_pool().await;
    let down = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy_with(PgConnectOptions::new().host("offline.invalid"));
    let codes = AuthCodes::with_db(pool.clone());
    let broken = spawn_gateway_with(
        &pool,
        ClientRegistry::with_db(down),
        codes.clone(),
        refresh(&pool),
    )
    .await;
    let healthy = spawn_gateway_with(
        &pool,
        ClientRegistry::with_db(pool.clone()),
        AuthCodes::with_db(pool.clone()),
        refresh(&pool),
    )
    .await;
    let (code, sub) = seed_code(&codes).await;

    let (status, body) = redeem(&broken, &code).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable");
    let (status, body) = redeem(&healthy, &code).await;
    assert_eq!(status, StatusCode::OK, "the retry redeems: {body}");
    delete_grants(&pool, &sub).await;
}

/// The mint's own statements fail before COMMIT: nothing exists, so the code
/// is put back and the retry, once the fault clears, redeems it.
#[tokio::test]
#[serial_test::serial(world)]
async fn a_mint_failing_before_commit_puts_the_code_back() {
    let pool = state_pool().await;
    let codes = AuthCodes::with_db(pool.clone());
    let gateway = spawn_gateway_with(
        &pool,
        ClientRegistry::with_db(pool.clone()),
        codes.clone(),
        refresh(&pool),
    )
    .await;
    let (code, sub) = seed_code(&codes).await;
    let trigger = format!("fail_mint_{}", Uuid::new_v4().simple());
    for ddl in [
        format!(
            "CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'mint refused by test'; END $$"
        ),
        format!(
            "CREATE TRIGGER {trigger} BEFORE INSERT ON oauth_refresh_tokens \
             FOR EACH ROW WHEN (NEW.user_sub = '{sub}') EXECUTE FUNCTION {trigger}()"
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(ddl))
            .execute(&pool)
            .await
            .expect("install");
    }

    let (failed, failed_body) = redeem(&gateway, &code).await;
    for ddl in [
        format!("DROP TRIGGER {trigger} ON oauth_refresh_tokens"),
        format!("DROP FUNCTION {trigger}()"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(ddl))
            .execute(&pool)
            .await
            .expect("uninstall");
    }
    assert_eq!(failed, StatusCode::SERVICE_UNAVAILABLE, "{failed_body}");
    let (status, body) = redeem(&gateway, &code).await;
    assert_eq!(status, StatusCode::OK, "the retry redeems: {body}");
    delete_grants(&pool, &sub).await;
}

async fn delete_grants(pool: &PgPool, sub: &str) {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_sub = $1")
        .bind(sub)
        .execute(pool)
        .await
        .expect("cleanup grants");
}

/// Rolling from a release that kept codes in process memory: a code the old
/// replica minted is unknown to the shared store, so a `/token` that lands on
/// a new replica is a clean `invalid_grant` (restart authorization), never a
/// 5xx and never a grant.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_code_minted_in_an_old_replicas_memory_is_invalid_grant() {
    let pool = state_pool().await;
    let old_replica = AuthCodes::default();
    let (code, sub) = seed_code(&old_replica).await;
    let new_replica = spawn_gateway_with(
        &pool,
        ClientRegistry::with_db(pool.clone()),
        AuthCodes::with_db(pool.clone()),
        refresh(&pool),
    )
    .await;

    let (status, body) = redeem(&new_replica, &code).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    delete_grants(&pool, &sub).await;
}
