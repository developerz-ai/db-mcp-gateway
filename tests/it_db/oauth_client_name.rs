//! RFC 7591 `client_name`: validated at `/register`, stored (migration 0019),
//! and shown escaped and labelled unverified on the consent page. Also proves
//! 0019 is rollback-tolerant: release 2.1.0's own client queries still run on
//! the new schema. Requires a running state Postgres (`bin/dev up`).

use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client};
use crate::common::idp::{MockUser, spawn_mock_idp};
use db_mcp_gateway::auth::oauth::ClientRegistry;
use serde_json::{Value, json};

const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const HTTPS_REDIRECT: &str = "https://named.example/cb";

const CONFIG_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: client name test
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: schema_read }
"#;

async fn spawn_gateway() -> String {
    let user = MockUser {
        sub: format!("name-user-{}", uuid::Uuid::new_v4().simple()),
        email: "user@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    GatewayBuilder::new(CONFIG_YAML)
        .idp(&idp)
        .spawn(state_pool().await)
        .await
        .url
}

async fn register(http: &reqwest::Client, gw: &str, name: &str) -> reqwest::Response {
    http.post(format!("{gw}/register"))
        .json(&json!({ "redirect_uris": [HTTPS_REDIRECT], "client_name": name }))
        .send()
        .await
        .unwrap()
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()["location"].to_str().unwrap().to_string()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn registered_name_is_shown_escaped_and_unverified_on_consent() {
    let gw = spawn_gateway().await;
    let http = no_redirect_client();
    let resp = register(&http, &gw, "  <script>alert(1)</script>  ").await;
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["client_name"], "<script>alert(1)</script>", "trimmed");
    let client_id = body["client_id"].as_str().unwrap();

    let authorize = http
        .get(format!("{gw}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", HTTPS_REDIRECT),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "s"),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        authorize.status().is_redirection(),
        "{}",
        authorize.status()
    );
    let idp = http.get(location(&authorize)).send().await.unwrap();
    let page = http
        .get(location(&idp))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(!page.contains("<script>alert"), "{page}");
    assert!(
        page.contains("class=\"client-name\">&lt;script&gt;alert(1)&lt;/script&gt;</span>"),
        "{page}"
    );
    assert!(page.contains("unverified"), "{page}");
    assert!(page.contains("class=\"host\">named.example<"), "{page}");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn invalid_names_are_invalid_client_metadata() {
    let gw = spawn_gateway().await;
    let http = no_redirect_client();
    for bad in [
        "a".repeat(101),
        "line\nbreak".into(),
        "rtl\u{202E}moc".into(),
    ] {
        let resp = register(&http, &gw, &bad).await;
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST, "{bad:?}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "invalid_client_metadata", "{bad:?}");
    }
    let ok = register(&http, &gw, &"a".repeat(100)).await;
    assert_eq!(ok.status(), reqwest::StatusCode::CREATED);
}

/// A 2.1.0 binary rolled back onto schema 0019 inserts and touches clients
/// with its own SQL (copied verbatim); the new binary reads such a row with no
/// name, and 2.1.0 still reads a row the new binary wrote with one.
#[tokio::test]
#[serial_test::parallel(world)]
async fn release_2_1_0_client_queries_run_on_the_0019_schema() {
    let pool = state_pool().await;
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_name = 'oauth_clients'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(columns.iter().any(|c| c == "client_name"), "{columns:?}");

    let old_id = format!("mcp-old-{}", uuid::Uuid::new_v4().simple());
    let inserted = sqlx::query(
        "INSERT INTO oauth_clients (client_id, redirect_uris, expires_at) \
         SELECT $1, $2, now() + interval '1 hour' \
         ON CONFLICT (client_id) DO UPDATE SET redirect_uris = EXCLUDED.redirect_uris",
    )
    .bind(&old_id)
    .bind(sqlx::types::Json(vec![HTTPS_REDIRECT]))
    .execute(&pool)
    .await
    .expect("2.1.0-shaped insert");
    assert_eq!(inserted.rows_affected(), 1);
    let registry = ClientRegistry::with_db(pool.clone());
    let record = registry.lookup(&old_id).await.expect("live");
    assert_eq!(record.redirect_uris, vec![HTTPS_REDIRECT.to_string()]);
    assert_eq!(record.client_name, None);

    let new_id = format!("mcp-new-{}", uuid::Uuid::new_v4().simple());
    let name = db_mcp_gateway::auth::oauth::ClientName::parse("Named").unwrap();
    registry
        .register(new_id.clone(), vec![HTTPS_REDIRECT.into()], name)
        .await
        .unwrap();
    let old_touch: Option<sqlx::types::Json<Vec<String>>> = sqlx::query_scalar(
        "UPDATE oauth_clients SET expires_at = now() + $2 \
         WHERE client_id = $1 AND expires_at > now() \
         RETURNING redirect_uris",
    )
    .bind(&new_id)
    .bind(chrono::Duration::days(90))
    .fetch_optional(&pool)
    .await
    .expect("2.1.0-shaped touch");
    assert_eq!(old_touch.map(|j| j.0), Some(vec![HTTPS_REDIRECT.into()]));

    sqlx::query("DELETE FROM oauth_clients WHERE client_id = ANY($1)")
        .bind(vec![old_id, new_id])
        .execute(&pool)
        .await
        .unwrap();
}
