//! `POST /admin/v1/explain` and grant `expires_at` over real HTTP + the real
//! state DB (plan 101 O10 b/c). Every explain asserts its `admin.explain`
//! audit row.

use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::json;

use crate::admin_o10_support::O10;

#[tokio::test]
#[serial_test::parallel(world)]
async fn explain_merges_yaml_group_and_db_user_grants_most_restrictive() {
    let mut h = O10::spawn().await;
    let (user_id, sub) = h.user("o10-explain", &["o10-eng"]).await;
    let db = h.wildcard_grant(user_id, json!({ "row_limit": 10 })).await;

    let (status, body) = h
        .post(
            "/admin/v1/explain",
            &json!({ "user": sub, "server": "prod", "database": "app", "action": "query_read" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "allow");
    assert_eq!(
        body["constraints"]["row_limit"], 10,
        "most restrictive wins"
    );
    assert_eq!(body["groups"], json!(["o10-eng"]), "cached groups used");
    let matched = body["matched"].as_array().expect("matched");
    assert_eq!(matched.len(), 2, "{body}");
    assert_eq!(matched[0]["source"], "yaml");
    assert_eq!(matched[0]["except"], json!(["billing"]));
    assert_eq!(matched[1]["grant_id"], json!(db.id));
    assert_eq!(h.admin_reads("admin.explain").await, 1);

    // `except: [billing]` takes the YAML grant away; the DB wildcard stays.
    let (_, body) = h
        .post(
            "/admin/v1/explain",
            &json!({ "user": sub, "server": "prod", "database": "billing",
                     "action": "query_read" }),
        )
        .await;
    assert_eq!(body["matched"].as_array().map(Vec::len), Some(1), "{body}");

    // A group question sees no DB grant and no user block.
    let (_, body) = h
        .post(
            "/admin/v1/explain",
            &json!({ "group": "nobody", "server": "prod", "database": "app",
                     "action": "query_read" }),
        )
        .await;
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["constraints"], json!(null));
    assert_eq!(h.admin_reads("admin.explain").await, 3);
    h.cleanup().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn expired_db_grant_is_denied_listed_expired_and_explained() {
    let mut h = O10::spawn().await;
    let (user_id, sub) = h.user("o10-expired", &[]).await;
    let grant = h.wildcard_grant(user_id, json!({})).await;
    // The API refuses a past expiry, so age the row directly: the boundary
    // itself (`now == expires_at` is expired) is unit-tested in authz.
    sqlx::query(
        "UPDATE permissions_grants SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(grant.id)
    .execute(&h.pool)
    .await
    .expect("age grant");

    let (_, body) = h
        .post(
            "/admin/v1/explain",
            &json!({ "user": sub, "server": "prod", "database": "app", "action": "query_read" }),
        )
        .await;
    assert_eq!(body["decision"], "deny", "{body}");
    assert_eq!(body["expired"][0]["grant_id"], json!(grant.id));
    assert_eq!(body["expired"][0]["expired"], true);

    let (status, list) = h.get(&format!("/admin/v1/grants?user_id={user_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list[0]["expired"], true, "{list}");
    assert!(list[0]["expires_at"].is_string());
    assert_eq!(h.admin_reads("admin.explain").await, 1);
    h.cleanup().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn grant_expiry_is_set_validated_and_cleared_through_the_api() {
    let mut h = O10::spawn().await;
    let (user_id, _) = h.user("o10-expiry", &[]).await;
    let at = Utc::now() + ChronoDuration::hours(1);
    let create = json!({ "user_id": user_id, "server": "prod", "db_name_wildcard": true,
                         "action": "query_read", "expires_at": at });
    let (status, grant) = h.post("/admin/v1/grants", &create).await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    assert_eq!(grant["expired"], false);
    let id = grant["id"].as_str().expect("id").to_string();

    let mut past = create.clone();
    past["expires_at"] = json!(Utc::now() - ChronoDuration::seconds(5));
    let (status, err) = h.post("/admin/v1/grants", &past).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"]["code"], "invalid_request");

    let resp = h
        .http()
        .patch(format!("{}/admin/v1/grants/{id}", h.url))
        .bearer_auth(&h.admin)
        .json(&json!({ "expires_at": null }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), StatusCode::OK);
    let patched: serde_json::Value = resp.json().await.expect("json");
    assert!(patched.get("expires_at").is_none(), "{patched}");
    let audit = h.audit_actions(id.parse().expect("uuid")).await;
    assert_eq!(audit, ["create", "update"]);
    let after: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT after FROM permissions_audit WHERE target_id = $1 AND action = 'create'",
    )
    .bind(uuid::Uuid::parse_str(&id).expect("uuid"))
    .fetch_one(&h.pool)
    .await
    .expect("create audit");
    assert!(
        after.expect("after")["expires_at"].is_string(),
        "expiry audited"
    );
    h.cleanup().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn explain_is_admin_gated_and_validates_its_subject() {
    let h = O10::spawn().await;
    let outsider = h.bearer(&h.admin_sub, &["not-admin"]).await;
    let resp = h
        .http()
        .post(format!("{}/admin/v1/explain", h.url))
        .bearer_auth(outsider)
        .json(&json!({ "group": "g", "server": "prod", "database": "app",
                       "action": "query_read" }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let (status, _) = h
        .post(
            "/admin/v1/explain",
            &json!({ "user": "a", "group": "b", "server": "prod", "database": "app",
                     "action": "query_read" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        h.admin_reads("admin.explain").await,
        0,
        "nothing read, nothing audited"
    );
    h.cleanup().await;
}
