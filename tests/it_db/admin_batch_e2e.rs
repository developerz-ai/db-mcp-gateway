//! `POST /admin/v1/grants/batch` (plan 101 O10 d): one transaction, one
//! `permissions_audit` row per applied change, all or nothing.

use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::admin_o10_support::{O10, wildcard_upsert};

async fn live_grants(h: &O10, user_id: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM permissions_grants WHERE user_id = $1 AND revoked_at IS NULL \
         ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&h.pool)
    .await
    .expect("grants")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn batch_creates_updates_and_deletes_with_one_audit_row_each() {
    let mut h = O10::spawn().await;
    let (a, _) = h.user("o10-batch-a", &[]).await;
    let (b, _) = h.user("o10-batch-b", &[]).await;
    let doomed = h.wildcard_grant(b, json!({})).await;
    let existing = h
        .wildcard_grant(
            a,
            json!({ "require_reason": false, "row_limit": 50,
                                   "statement_timeout_ms": null }),
        )
        .await;

    let (status, body) = h
        .post(
            "/admin/v1/grants/batch",
            &json!({ "changes": [
                wildcard_upsert(a, 5),
                { "op": "delete", "id": doomed.id },
                { "op": "upsert", "user_id": b, "server": "prod", "db_name_wildcard": true,
                  "action": "schema_read" },
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ops: Vec<_> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| r["op"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(ops, ["updated", "deleted", "created"]);
    assert_eq!(
        body["results"][0]["id"],
        json!(existing.id),
        "upsert keyed in place"
    );
    assert_eq!(body["results"][0]["grant"]["constraints"]["row_limit"], 5);

    assert_eq!(h.audit_actions(existing.id).await, ["update"]);
    assert_eq!(h.audit_actions(doomed.id).await, ["delete"]);
    let created: Uuid = body["results"][2]["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("uuid");
    assert_eq!(h.audit_actions(created).await, ["create"]);
    assert_eq!(live_grants(&h, b).await, [created]);

    // Re-applying the same upsert changes nothing and audits nothing.
    let (_, again) = h
        .post(
            "/admin/v1/grants/batch",
            &json!({ "changes": [wildcard_upsert(a, 5)] }),
        )
        .await;
    assert_eq!(again["results"][0]["op"], "unchanged");
    assert_eq!(h.audit_actions(existing.id).await, ["update"]);
    h.cleanup().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_failing_change_rolls_back_the_whole_batch() {
    let mut h = O10::spawn().await;
    let (a, _) = h.user("o10-batch-rollback", &[]).await;
    let (status, body) = h
        .post(
            "/admin/v1/grants/batch",
            &json!({ "changes": [
                wildcard_upsert(a, 7),
                { "op": "delete", "id": Uuid::new_v4() },
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.starts_with("changes[1]: "), "{message}");
    assert!(
        live_grants(&h, a).await.is_empty(),
        "first change rolled back"
    );
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM permissions_audit WHERE after->>'user_id' = $1")
            .bind(a.to_string())
            .fetch_one(&h.pool)
            .await
            .expect("audit count");
    assert_eq!(audited, 0, "no audit row survives a rolled-back batch");

    let (status, _) = h
        .post("/admin/v1/grants/batch", &json!({ "changes": [] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an empty batch is refused");
    h.cleanup().await;
}

/// A batch at its 500-change maximum is past the 64 KiB every other admin
/// body gets; it has its own byte bound, and a body past that is refused as
/// `413 payload_too_large`, not mistaken for malformed JSON.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_full_batch_fits_its_body_bound_and_a_larger_body_is_413() {
    let mut h = O10::spawn().await;
    let (a, _) = h.user("o10-batch-full", &[]).await;
    let changes: Vec<_> = (0..500).map(|_| wildcard_upsert(a, 5)).collect();
    let full = json!({ "changes": changes });
    assert!(full.to_string().len() > 64 * 1024);

    let (status, body) = h.post("/admin/v1/grants/batch", &full).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["results"].as_array().map(Vec::len), Some(500));

    // Valid JSON, one change, padded past the bound with whitespace.
    let padded = format!(
        "{{\"changes\": [{}]{}}}",
        wildcard_upsert(a, 5),
        " ".repeat(1024 * 1024 + 1)
    );
    let resp = h
        .http()
        .post(format!("{}/admin/v1/grants/batch", h.url))
        .bearer_auth(&h.admin)
        .header("content-type", "application/json")
        .body(padded)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: serde_json::Value = resp.json().await.expect("json error body");
    assert_eq!(body["error"]["code"], "payload_too_large", "{body}");
    assert!(body["error"]["request_id"].is_string(), "{body}");
    h.cleanup().await;
}
