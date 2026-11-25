use axum::body::to_bytes;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::*;
use crate::auth::oauth::{AuthCodes, ClientRegistry, GrantIdentity};
use crate::transport::app_state::offline_for_tests;

// RFC 7636 Appendix B test vector.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "http://127.0.0.1:54601/callback";
const CODE: &str = "one-time-code";

async fn state_holding_a_code() -> OAuthState {
    let state = offline_for_tests().oauth;
    let identity = GrantIdentity {
        sub: "u1".into(),
        email: "u1@example.com".into(),
        groups: vec!["eng".into()],
    };
    let (challenge, redirect) = (CHALLENGE.to_string(), REDIRECT.to_string());
    state
        .auth
        .codes
        .insert(CODE, identity, challenge, redirect, "client-1".into())
        .await
        .expect("code stored");
    state
}

async fn redeem(state: &OAuthState) -> (StatusCode, Value) {
    let form = TokenForm {
        grant_type: Some("authorization_code".into()),
        code: Some(CODE.into()),
        redirect_uri: Some(REDIRECT.into()),
        code_verifier: Some(VERIFIER.into()),
        refresh_token: None,
        client_id: Some("client-1".into()),
        resource: None,
    };
    let response = token(State(state.clone()), Ok(Form(form))).await;
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.expect("body");
    (status, serde_json::from_slice(&body).expect("json body"))
}

/// The registry's state DB is down at promotion: `/token` says "try again",
/// so the retry must find the code — nothing was issued against it.
#[tokio::test]
async fn a_failed_promotion_leaves_the_code_redeemable() {
    let mut state = state_holding_a_code().await;
    let down = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy_with(PgConnectOptions::new().host("offline.invalid"));
    state.client_registry = ClientRegistry::with_db(down);

    let (status, body) = redeem(&state).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(
        state
            .auth
            .codes
            .take(CODE)
            .await
            .expect("memory take")
            .is_some(),
        "a retryable 503 consumed the authorization code"
    );
}

/// Same contract when the mint itself fails (state DB down): no session, no
/// token, and the code is still there for the retry.
#[tokio::test]
async fn a_failed_mint_leaves_the_code_redeemable() {
    let state = state_holding_a_code().await;

    let (status, body) = redeem(&state).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(
        state
            .auth
            .codes
            .take(CODE)
            .await
            .expect("memory take")
            .is_some(),
        "a retryable 503 consumed the authorization code"
    );
}

/// A redemption refused for what the client sent is final: the code stays
/// consumed, so a guessed verifier gets one attempt.
#[tokio::test]
async fn a_failed_pkce_check_still_consumes_the_code() {
    let state = state_holding_a_code().await;
    let form = TokenForm {
        grant_type: Some("authorization_code".into()),
        code: Some(CODE.into()),
        redirect_uri: Some(REDIRECT.into()),
        code_verifier: Some("wrong-verifier".into()),
        refresh_token: None,
        client_id: None,
        resource: None,
    };
    let response = token(State(state.clone()), Ok(Form(form))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state
            .auth
            .codes
            .take(CODE)
            .await
            .expect("memory take")
            .is_none()
    );
}

/// The code store itself is unreachable: nothing was taken or issued, so the
/// client is told to retry rather than to restart authorization.
#[tokio::test]
async fn an_unreachable_code_store_is_a_retryable_503() {
    let mut state = offline_for_tests().oauth;
    let down = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy_with(PgConnectOptions::new().host("offline.invalid"));
    state.auth.codes = AuthCodes::with_db(down);

    let (status, body) = redeem(&state).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
}

/// A full store and a refused statement keep their own answer: only a dead
/// state DB is `temporarily_unavailable`.
#[tokio::test]
async fn a_full_store_and_a_refused_statement_stay_server_error() {
    let cases = [
        (
            AuthError::StoreFull,
            "gateway temporarily overloaded; try again",
        ),
        (
            AuthError::State(sqlx::Error::RowNotFound),
            "could not issue tokens; try again",
        ),
    ];
    for (err, description) in cases {
        let response = token_response(Err(err));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body: Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(body["error"], "server_error");
        assert_eq!(body["error_description"], description);
    }
}

/// A refresh during the outage asks for a retry, not for a new login.
#[tokio::test]
async fn a_refresh_the_state_db_cannot_serve_is_temporarily_unavailable() {
    let mut state = offline_for_tests().oauth;
    let down = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy_with(PgConnectOptions::new().host("offline.invalid"));
    state.auth.refresh =
        crate::auth::oauth::RefreshTokens::with_db(down, std::time::Duration::from_secs(60));
    let form = TokenForm {
        grant_type: Some("refresh_token".into()),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: Some("any".into()),
        client_id: None,
        resource: None,
    };
    let response = token(State(state), Ok(Form(form))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 4096).await.expect("body");
    let body: Value = serde_json::from_slice(&body).expect("json body");
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(!body.to_string().contains("offline.invalid"), "{body}");
}
