//! `admin.session_max_age_secs` read from YAML caps how old a session may be
//! on `/admin/v1/*` (spec 12 §"Admin API"): the same bearer that just listed
//! users is refused `403 session_too_old` once it outlives the cap.

use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::Value;

use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;

const YAML: &str = r#"
servers: []
permissions: []
admin:
  enabled: true
  group: gateway-admins
  session_max_age_secs: 1
"#;

async fn list_users(gw: &LoggedInGateway) -> (StatusCode, Value) {
    let resp = reqwest::Client::new()
        .get(format!("{}/admin/v1/users", gw.url))
        .bearer_auth(&gw.bearer)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn an_admin_session_older_than_the_yaml_cap_is_session_too_old() {
    let user = MockUser {
        sub: format!("admin-age-{}", uuid::Uuid::new_v4().simple()),
        email: "admin-age@example.com".to_string(),
        groups: vec!["gateway-admins".to_string()],
    };
    let logged_in = Instant::now();
    let gw = spawn_logged_in(YAML, user).await;
    let (fresh, body) = list_users(&gw).await;
    assert_eq!(fresh, StatusCode::OK, "a fresh admin session lists: {body}");

    // Poll until the cap bites; the deadline bounds a cap that never does.
    let deadline = logged_in + Duration::from_secs(10);
    let (status, body) = loop {
        let (status, body) = list_users(&gw).await;
        if status != StatusCode::OK || Instant::now() > deadline {
            break (status, body);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "session_too_old", "{body}");
    assert!(
        logged_in.elapsed() >= Duration::from_secs(1),
        "refused before the 1 s cap: {body}"
    );
}
