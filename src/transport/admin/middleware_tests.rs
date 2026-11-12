//! Unit tests for `require_admin_group`'s session-age gate.

use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;

use super::*;
use crate::auth::SessionId;

/// Build an `Identity` with the given group list and `issued_at` offset from
/// now. Positive = issued N seconds ago; negative = issued in the future
/// (used to exercise the clock-skew guard).
fn make_identity(groups: &[&str], issued_secs_ago: i64) -> Identity {
    let now = Utc::now();
    Identity {
        session_id: SessionId::new(),
        user_sub: "u".to_string(),
        user_email: "u@example.com".to_string(),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        issued_at: now - chrono::Duration::seconds(issued_secs_ago),
        kind: crate::auth::IdentityKind::Sso,
    }
}

#[test]
fn session_too_old_renders_403_with_stable_code() {
    let err = AdminError::session_too_old().with_request_id("req-1");
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_too_old_body_has_stable_code() {
    let resp = AdminError::session_too_old()
        .with_request_id("req-1")
        .into_response();
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "session_too_old");
    assert_eq!(body["error"]["request_id"], "req-1");
}

/// Young-enough session passes the age gate.
#[test]
fn fresh_session_passes_age_gate() {
    let identity = make_identity(&["admins"], 30); // 30 s old
    let max_age = Duration::from_secs(3600); // 1 h limit
    let age = Utc::now()
        .signed_duration_since(identity.issued_at)
        .to_std()
        .unwrap();
    assert!(
        age <= max_age,
        "30 s session should pass a 3600 s age limit"
    );
}

/// Session older than `max_session_age` must be rejected.
#[test]
fn stale_session_exceeds_age_gate() {
    let identity = make_identity(&["admins"], 7201); // 2 h + 1 s old
    let max_age = Duration::from_secs(3600); // 1 h limit
    let age = Utc::now()
        .signed_duration_since(identity.issued_at)
        .to_std()
        .unwrap();
    assert!(
        age > max_age,
        "7201 s session should exceed a 3600 s age limit"
    );
}

/// `issued_at` in the future (clock skew / NTP jump / forged token) must
/// fail closed: the age is unmeasurable (`to_std()` errors on the negative
/// duration), so the middleware rejects with `session_too_old` (403) rather
/// than treating the session as fresh and bypassing the age cap.
#[test]
fn future_issued_at_fails_closed() {
    let identity = make_identity(&["admins"], -120); // issued 2 min in future
    // A future issued_at yields a negative duration, which `to_std()` can't
    // represent → Err. The middleware maps that Err to a rejection.
    let measured = Utc::now()
        .signed_duration_since(identity.issued_at)
        .to_std();
    assert!(
        measured.is_err(),
        "future issued_at should be unmeasurable, triggering fail-closed"
    );
    let resp = AdminError::session_too_old()
        .with_request_id("req-skew")
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
