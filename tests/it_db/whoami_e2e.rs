//! `whoami` over real HTTP (plan 101 slice 06, M11): the caller's own
//! identity, groups, session expiry and grants — for an SSO session and a
//! service account — each call audited, no target reached (the fixture's
//! hosts are unresolvable). Shares `discovery_e2e`'s fixture.

use crate::common::audit::{assert_audit_outcome, latest_audit};
use serde_json::json;

use super::discovery_e2e::{SVC_TOKEN, assert_no_credentials, boot, call, database_ids, payload};

/// M11: an SSO caller's own identity, session expiry and every grant —
/// `history_read`-only databases included — audited, no target reached.
#[tokio::test]
#[serial_test::parallel(world)]
async fn whoami_reports_sso_identity_session_and_grants() {
    let gw = boot().await;
    let envelope = call(&gw, &gw.bearer, "whoami", None).await;
    assert_no_credentials(&envelope);
    let body = payload(&envelope);
    assert_eq!(body["sub"], gw.user_sub.as_str());
    assert_eq!(body["email"], "discovery@example.com");
    assert_eq!(body["auth"], "sso");
    assert_eq!(body["groups"], json!(["discoverers"]));
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(body["session_expires_at"].clone()).expect("RFC 3339 expiry");
    assert!(
        expires > chrono::Utc::now(),
        "live session expires in the future"
    );
    assert_eq!(
        database_ids(&body["grants"]),
        vec!["prod/app", "prod/billing", "prod/sandbox", "docs/content"]
    );

    let row = latest_audit(&gw.state_db, &gw.user_sub, "whoami", "whoami").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.server, None);
    assert_eq!(row.database, None);
    assert_eq!(row.row_count, Some(4));
}

/// M11: a service account sees its name, its one group, no session, and
/// only its own group's grants — never the human's.
#[tokio::test]
#[serial_test::parallel(world)]
async fn whoami_reports_service_account() {
    let gw = boot().await;
    let body = payload(&call(&gw, SVC_TOKEN, "whoami", Some(json!({}))).await);
    assert_eq!(body["sub"], "service:discovery-bot");
    assert_eq!(body["auth"], "service");
    assert_eq!(body["service_account"], "discovery-bot");
    assert_eq!(body["groups"], json!(["svc-discovery"]));
    assert!(body.get("session_expires_at").is_none(), "{body}");
    assert_eq!(database_ids(&body["grants"]), vec!["docs/content"]);
    assert_audit_outcome(
        &gw.state_db,
        "service:discovery-bot",
        "whoami",
        "success",
        "svc",
    )
    .await;
}

/// An unknown argument is `invalid_arguments`, audited.
#[tokio::test]
#[serial_test::parallel(world)]
async fn whoami_rejects_unknown_arguments() {
    let gw = boot().await;
    let envelope = call(
        &gw,
        &gw.bearer,
        "whoami",
        Some(json!({ "user": "someone-else" })),
    )
    .await;
    assert!(envelope.get("error").is_some(), "{envelope}");
    assert_audit_outcome(
        &gw.state_db,
        &gw.user_sub,
        "whoami",
        "invalid_arguments",
        "bad args",
    )
    .await;
}
