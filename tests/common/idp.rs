//! In-process mock OIDC IdPs, signed with a static RSA
//! keypair committed under `tests/data/`. [`spawn_mock_idp`] walks the full
//! login flow without a real IdP (see `auth_e2e.rs`); [`spawn_token_idp`] is
//! discovery, JWKS and a token endpoint only, for tests that drive
//! `OidcClient` verification directly with a hand-built ID token.
//!
//! Not security-sensitive: the private key is plainly in the repo, only used
//! by tests, and never touches a production code path.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use uuid::Uuid;

const TEST_KEY_PEM: &str = include_str!("../data/test_idp_key.pem");
const TEST_JWK: &str = include_str!("../data/test_idp_pub.jwk.json");
/// The `kid` the committed JWKS publishes.
pub const TEST_KID: &str = "test-kid-1";
/// Fixed HMAC secret used only when `MockTokenFlags::sign_with_hs256` is set.
/// Never used in production; exists solely to mint an HS256 token the gateway
/// must reject (A5 — algorithm pinned to RS256).
const HS256_TEST_SECRET: &[u8] = b"test-hs256-secret-not-a-real-key";

/// Controls what the mock IdP injects into the ID token.
///
/// `Default` (all-false) → normal behaviour: RS256-signed, email verified.
/// Use [`spawn_mock_idp_with_flags`] to exercise non-default paths; the
/// baseline [`spawn_mock_idp`] delegates here with the default flags.
#[derive(Clone, Debug, Default)]
pub struct MockTokenFlags {
    /// Sign the ID token with HS256 instead of RS256.  Simulates an
    /// algorithm-confusion attack; the gateway must reject it because
    /// `Validation::new(Algorithm::RS256)` pins the allowed algorithm (A5).
    pub sign_with_hs256: bool,
    /// Emit `email_verified: false` in the ID token claims.  The gateway must
    /// reject the resulting identity because unverified e-mail cannot be used
    /// as the audit/admin identity (A6).
    pub unverified_email: bool,
    /// Emit a future-dated `nbf` (not-before) claim.  The gateway must reject
    /// the token as not-yet-valid (`Validation::validate_nbf`).
    pub future_nbf: bool,
}

#[derive(Clone, Debug)]
pub struct MockUser {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

#[derive(Debug)]
pub struct MockIdpHandle {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone)]
struct MockIdpState {
    issuer: String,
    client_id: String,
    client_secret: String,
    user: MockUser,
    /// `code → (nonce, pkce_challenge)`, populated by /authorize and consumed
    /// by /token. Storing the challenge lets /token enforce PKCE — proving the
    /// gateway (as an OAuth client) actually sends a verifier.
    codes: Arc<Mutex<HashMap<String, (String, String)>>>,
    flags: MockTokenFlags,
}

pub async fn spawn_mock_idp(client_id: &str, client_secret: &str, user: MockUser) -> MockIdpHandle {
    spawn_mock_idp_with_flags(client_id, client_secret, user, MockTokenFlags::default()).await
}

/// Like [`spawn_mock_idp`] but lets the caller inject token-level deviations
/// (wrong algorithm, unverified email) to test gateway rejection paths.
pub async fn spawn_mock_idp_with_flags(
    client_id: &str,
    client_secret: &str,
    user: MockUser,
    flags: MockTokenFlags,
) -> MockIdpHandle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock IdP");
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let state = MockIdpState {
        issuer: issuer.clone(),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        user,
        codes: Arc::new(Mutex::new(HashMap::new())),
        flags,
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    MockIdpHandle {
        issuer,
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
    }
}

async fn discovery(State(s): State<MockIdpState>) -> Json<Value> {
    Json(discovery_document(&s.issuer))
}

async fn jwks(State(_): State<MockIdpState>) -> Json<Value> {
    Json(jwks_document())
}

fn discovery_document(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })
}

fn jwks_document() -> Value {
    let jwk: Value = serde_json::from_str(TEST_JWK).expect("static JWK is valid JSON");
    json!({ "keys": [jwk] })
}

/// Seconds since the UNIX epoch, for `iat` / `exp` / `nbf`.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock past UNIX epoch")
        .as_secs()
}

/// RS256-sign `claims` with the committed test key, naming `kid`.
pub fn sign_rs256(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("static test key parses"),
    )
    .expect("ID token encoding never fails for our static inputs")
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
    nonce: String,
    response_type: String,
    client_id: String,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    _scope: Option<String>,
}

async fn authorize(
    State(s): State<MockIdpState>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Redirect, StatusCode> {
    // Catch regressions in the gateway's request composition: missing or wrong
    // OIDC protocol fields should fail the test, not silently pass.
    if q.response_type != "code" || q.client_id != s.client_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    // PKCE S256 is mandatory (mirrors IdPs whose /authorize requires it). The gateway, acting
    // as an OAuth client, MUST send a challenge — absence is a regression.
    let challenge = match (q.code_challenge, q.code_challenge_method.as_deref()) {
        (Some(c), Some("S256")) if !c.is_empty() => c,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let code = Uuid::new_v4().simple().to_string();
    s.codes
        .lock()
        .await
        .insert(code.clone(), (q.nonce, challenge));
    let target = format!("{}?code={}&state={}", q.redirect_uri, code, q.state);
    Ok(Redirect::temporary(&target))
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    code: String,
    grant_type: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    _redirect_uri: Option<String>,
}

async fn token(
    State(s): State<MockIdpState>,
    Form(form): Form<TokenForm>,
) -> Result<Json<Value>, StatusCode> {
    if form.grant_type != "authorization_code"
        || form.client_id != s.client_id
        || form.client_secret != s.client_secret
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (nonce, challenge) = s
        .codes
        .lock()
        .await
        .remove(&form.code)
        .ok_or(StatusCode::BAD_REQUEST)?;
    // Enforce PKCE: the gateway must present a verifier matching the challenge
    // it sent at /authorize (RFC 7636). A missing/bad verifier is rejected.
    let verifier = form
        .code_verifier
        .as_deref()
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !db_mcp_gateway::auth::pkce::verify(verifier, &challenge) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id_token = sign_id_token(&s.issuer, &s.client_id, &s.user, &nonce, &s.flags);
    Ok(Json(json!({
        "access_token": "test-access",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    })))
}

fn sign_id_token(
    issuer: &str,
    aud: &str,
    user: &MockUser,
    nonce: &str,
    flags: &MockTokenFlags,
) -> String {
    let now = now_secs();
    let email_verified = !flags.unverified_email;
    let mut claims = json!({
        "iss": issuer,
        "sub": user.sub,
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
        "email": user.email,
        "email_verified": email_verified,
        "groups": user.groups,
    });
    if flags.future_nbf {
        // 10 minutes ahead — well past any clock-skew leeway, so the token is
        // unambiguously not-yet-valid. `exp` stays an hour out, isolating the
        // rejection to the `nbf` check.
        claims["nbf"] = json!(now + 600);
    }
    if flags.sign_with_hs256 {
        // HS256 token: the gateway fetches the RSA public key by kid, then calls
        // jsonwebtoken::decode with Algorithm::RS256 — the alg mismatch is caught
        // before any crypto, exercising the A5 pin.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_secret(HS256_TEST_SECRET),
        )
        .expect("HS256 encoding never fails for our static inputs")
    } else {
        sign_rs256(&claims, TEST_KID)
    }
}

/// What the verify-only IdP's token endpoint was sent.
#[derive(Debug)]
pub struct TokenRequest {
    /// The IdP's own issuer URL, for the `iss` claim.
    pub issuer: String,
    pub headers: HeaderMap,
    pub form: HashMap<String, String>,
}

type MintIdToken = dyn Fn(&TokenRequest) -> Result<String, StatusCode> + Send + Sync;

struct TokenIdpState {
    issuer: String,
    jwks_hits: Arc<AtomicUsize>,
    mint: Box<MintIdToken>,
}

/// A running [`spawn_token_idp`].
#[derive(Debug)]
pub struct TokenIdp {
    pub issuer: String,
    /// JWKS fetches served so far.
    pub jwks_hits: Arc<AtomicUsize>,
}

/// Discovery, JWKS and a token endpoint that accepts any code and answers
/// with the ID token `mint` builds — or `mint`'s status, e.g. a 401 for
/// client credentials it refuses. No `/authorize`: the caller skips straight
/// to `OidcClient::exchange_and_verify`.
pub async fn spawn_token_idp(
    mint: impl Fn(&TokenRequest) -> Result<String, StatusCode> + Send + Sync + 'static,
) -> TokenIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock IdP");
    let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(TokenIdpState {
        issuer: issuer.clone(),
        jwks_hits: Arc::clone(&jwks_hits),
        mint: Box::new(mint),
    });
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|State(s): State<Arc<TokenIdpState>>| async move {
                Json(discovery_document(&s.issuer))
            }),
        )
        .route(
            "/jwks.json",
            get(|State(s): State<Arc<TokenIdpState>>| async move {
                s.jwks_hits.fetch_add(1, Ordering::SeqCst);
                Json(jwks_document())
            }),
        )
        .route("/token", post(token_only))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    TokenIdp { issuer, jwks_hits }
}

async fn token_only(
    State(s): State<Arc<TokenIdpState>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let request = TokenRequest {
        issuer: s.issuer.clone(),
        headers,
        form,
    };
    let id_token = (s.mint)(&request)?;
    Ok(Json(json!({
        "access_token": "test-access",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    })))
}
