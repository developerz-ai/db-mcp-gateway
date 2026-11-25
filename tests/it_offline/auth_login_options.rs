//! The IdP-facing login options (`OIDC_SCOPES`, `OIDC_TOKEN_AUTH_METHOD`,
//! `OIDC_GROUPS_PREFIX`) and the groups-claim shapes real IdPs emit, driven
//! through `OidcClient` against `common::idp`'s verify-only IdP: discovery,
//! JWKS and a token endpoint only.

use axum::http::{HeaderMap, StatusCode};
use base64::Engine;
use db_mcp_gateway::auth::{AuthConfig, AuthError, LoginOptions, OidcClient, VerifiedIdentity};
use serde_json::{Value, json};

use crate::common::idp::{TEST_KID, TokenRequest, now_secs, sign_rs256, spawn_token_idp};

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

struct Login {
    claim: &'static str,
    groups: Value,
    /// The one way the IdP accepts client credentials, as some Okta apps do.
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
    let Login {
        claim,
        groups,
        accepts,
        options: vars,
    } = login;
    let idp = spawn_token_idp(move |req| {
        if presented_credentials(req, accepts)
            != Some((CLIENT_ID.to_owned(), CLIENT_SECRET.to_owned()))
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(sign_id_token(&req.issuer, claim, &groups))
    })
    .await;
    OidcClient::with_options(
        AuthConfig {
            issuer: idp.issuer,
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.into(),
            audience: CLIENT_ID.to_owned(),
            groups_claim: claim.to_owned(),
            ..AuthConfig::default()
        },
        options(vars),
    )
    .expect("OidcClient http builder")
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

/// The client credentials, if sent the one way the IdP accepts.
fn presented_credentials(req: &TokenRequest, accepts: ClientAuth) -> Option<(String, String)> {
    let in_form = (req.form.get("client_id"), req.form.get("client_secret"));
    match accepts {
        ClientAuth::Post if req.headers.get("authorization").is_none() => match in_form {
            (Some(id), Some(secret)) => Some((id.clone(), secret.clone())),
            _ => None,
        },
        ClientAuth::Basic if in_form.1.is_none() => basic_credentials(&req.headers),
        _ => None,
    }
}

fn sign_id_token(issuer: &str, claim: &str, groups: &Value) -> String {
    let now = now_secs();
    let mut claims = json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": "options-subject",
        "exp": now + 3600,
        "iat": now,
        "nonce": NONCE,
        "email": "options@example.com",
        "email_verified": true,
    });
    claims[claim] = groups.clone();
    sign_rs256(&claims, TEST_KID)
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
