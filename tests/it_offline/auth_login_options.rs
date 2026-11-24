//! The IdP-facing login options (`OIDC_SCOPES`, `OIDC_TOKEN_AUTH_METHOD`,
//! `OIDC_GROUPS_PREFIX`) and the groups-claim shapes real IdPs emit, driven
//! through `OidcClient` against an in-process IdP. Self-contained like
//! `auth_hardening_id_token`: discovery, JWKS and a token endpoint only.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use db_mcp_gateway::auth::{AuthConfig, AuthError, LoginOptions, OidcClient, VerifiedIdentity};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::collections::HashMap;

const TEST_KEY_PEM: &str = include_str!("../data/test_idp_key.pem");
const TEST_JWK: &str = include_str!("../data/test_idp_pub.jwk.json");
const TEST_KID: &str = "test-kid-1";
const CLIENT_ID: &str = "options-client";
/// `:` and `/` must survive Basic encoding (RFC 6749 §2.3.1).
const CLIENT_SECRET: &str = "s3cr:t/+";
const NONCE: &str = "options-nonce";
const ZITADEL_CLAIM: &str = "urn:zitadel:iam:org:project:2901:roles";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientAuth {
    Post,
    Basic,
}

#[derive(Clone, Debug)]
struct MockIdp {
    issuer: String,
    /// The one way this IdP accepts client credentials, as some Okta apps do.
    accepts: ClientAuth,
    claim: &'static str,
    groups: Value,
}

struct Login {
    claim: &'static str,
    groups: Value,
    accepts: ClientAuth,
    options: &'static [(&'static str, &'static str)],
}

impl Default for Login {
    fn default() -> Self {
        Self {
            claim: "groups",
            groups: json!(["engineers"]),
            accepts: ClientAuth::Post,
            options: &[],
        }
    }
}

fn options(vars: &[(&str, &str)]) -> LoginOptions {
    LoginOptions::from_lookup(|var| {
        vars.iter()
            .find(|(name, _)| *name == var)
            .map(|(_, value)| (*value).to_owned())
    })
    .expect("valid login options")
}

async fn client(login: Login) -> OidcClient {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock IdP");
    let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
    let idp = MockIdp {
        issuer: issuer.clone(),
        accepts: login.accepts,
        claim: login.claim,
        groups: login.groups,
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks))
        .route("/token", post(token))
        .with_state(Arc::new(idp));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    OidcClient::with_options(
        AuthConfig {
            issuer,
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.into(),
            audience: CLIENT_ID.to_owned(),
            groups_claim: login.claim.to_owned(),
            ..AuthConfig::default()
        },
        options(login.options),
    )
    .expect("OidcClient http builder")
}

async fn discovery(State(idp): State<Arc<MockIdp>>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks.json", idp.issuer),
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn jwks() -> Json<Value> {
    let jwk: Value = serde_json::from_str(TEST_JWK).expect("static JWK is valid JSON");
    Json(json!({ "keys": [jwk] }))
}

/// `(id, secret)` from a Basic header, each form-urldecoded.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let encoded = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let (id, secret) = std::str::from_utf8(&decoded).ok()?.split_once(':')?;
    let unescape = |raw: &str| {
        url::form_urlencoded::parse(format!("v={raw}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
    };
    Some((unescape(id)?, unescape(secret)?))
}

async fn token(
    State(idp): State<Arc<MockIdp>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let in_form = (form.get("client_id"), form.get("client_secret"));
    let presented = match idp.accepts {
        ClientAuth::Post if headers.get("authorization").is_none() => match in_form {
            (Some(id), Some(secret)) => Some((id.clone(), secret.clone())),
            _ => None,
        },
        ClientAuth::Basic if in_form.1.is_none() => basic_credentials(&headers),
        _ => None,
    };
    if presented != Some((CLIENT_ID.to_owned(), CLIENT_SECRET.to_owned())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(json!({
        "access_token": "options-access",
        "token_type": "Bearer",
        "id_token": sign_id_token(&idp),
    })))
}

fn sign_id_token(idp: &MockIdp) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock past UNIX epoch")
        .as_secs();
    let mut claims = json!({
        "iss": idp.issuer,
        "aud": CLIENT_ID,
        "sub": "options-subject",
        "exp": now + 3600,
        "iat": now,
        "nonce": NONCE,
        "email": "options@example.com",
        "email_verified": true,
    });
    claims[idp.claim] = idp.groups.clone();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("static test key parses"),
    )
    .expect("ID token encoding never fails for our static inputs")
}

async fn login(login: Login) -> Result<VerifiedIdentity, AuthError> {
    client(login)
        .await
        .exchange_and_verify("any-code", NONCE, "any-verifier")
        .await
}

async fn groups_of(login_spec: Login) -> Vec<String> {
    login(login_spec).await.expect("login verifies").groups
}

#[tokio::test]
async fn a_flat_groups_array_is_read_as_is() {
    let groups = groups_of(Login {
        groups: json!(["db-oncall", "db-readers"]),
        ..Login::default()
    })
    .await;
    assert_eq!(groups, ["db-oncall", "db-readers"]);
}

#[tokio::test]
async fn a_zitadel_roles_object_yields_its_role_names() {
    let groups = groups_of(Login {
        claim: ZITADEL_CLAIM,
        groups: json!({
            "db-oncall": {"2901": "acme.zitadel.cloud"},
            "db-readers": {"2901": "acme.zitadel.cloud"},
        }),
        ..Login::default()
    })
    .await;
    assert_eq!(groups, ["db-oncall", "db-readers"]);
}

#[tokio::test]
async fn the_groups_prefix_filters_and_strips() {
    let groups = groups_of(Login {
        groups: json!(["dbmcp-oncall", "hr-admins", "dbmcp-readers"]),
        options: &[("OIDC_GROUPS_PREFIX", "dbmcp-")],
        ..Login::default()
    })
    .await;
    assert_eq!(groups, ["oncall", "readers"]);
}

#[tokio::test]
async fn an_unreadable_claim_shape_logs_in_with_no_groups() {
    for shape in [json!("db-oncall"), json!(42), json!(true)] {
        let groups = groups_of(Login {
            groups: shape.clone(),
            ..Login::default()
        })
        .await;
        assert!(groups.is_empty(), "{shape} gave {groups:?}");
    }
}

#[tokio::test]
async fn client_secret_basic_reaches_an_idp_that_accepts_only_basic() {
    let basic = Login {
        accepts: ClientAuth::Basic,
        options: &[("OIDC_TOKEN_AUTH_METHOD", "client_secret_basic")],
        ..Login::default()
    };
    assert_eq!(login(basic).await.expect("basic").groups, ["engineers"]);

    // The default (post) is refused by the same IdP: the option is what works.
    let post = Login {
        accepts: ClientAuth::Basic,
        ..Login::default()
    };
    assert!(matches!(login(post).await, Err(AuthError::CodeExchange)));
}

#[tokio::test]
async fn client_secret_post_stays_the_default() {
    assert_eq!(
        groups_of(Login::default()).await,
        ["engineers"],
        "secret in the form body"
    );
}

#[tokio::test]
async fn authorize_url_asks_for_the_configured_scopes() {
    let scope_of = |url: url::Url| {
        url.query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.into_owned())
    };
    let default = client(Login::default()).await;
    let url = default.authorize_url("s", "n", "c").await.expect("url");
    assert_eq!(
        scope_of(url).as_deref(),
        Some("openid email profile groups")
    );

    let google = client(Login {
        options: &[("OIDC_SCOPES", "openid email profile")],
        ..Login::default()
    })
    .await;
    let url = google.authorize_url("s", "n", "c").await.expect("url");
    assert_eq!(scope_of(url).as_deref(), Some("openid email profile"));
}
