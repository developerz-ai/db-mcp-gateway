use axum::http::HeaderValue;
use chrono::Utc;

use super::*;
use crate::auth::SessionId;

fn identity(kind: IdentityKind) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: "service:fleet".into(),
        user_email: "fleet@service-accounts.invalid".into(),
        groups: vec!["agents".into()],
        issued_at: Utc::now(),
        kind,
    }
}

fn policy(require_upstream: bool) -> ServicePolicy {
    ServicePolicy {
        require_upstream,
        max_concurrent_requests: None,
    }
}

fn headers(pairs: &[(&HeaderName, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(*name, HeaderValue::from_str(value).unwrap());
    }
    map
}

#[test]
fn service_caller_claims_are_kept() {
    let map = headers(&[
        (&RUN_ID_HEADER, "run-42"),
        (&ON_BEHALF_OF_HEADER, "alice@example.com"),
    ]);
    let got = from_headers(&map, &identity(IdentityKind::Service), Some(&policy(false)));
    assert_eq!(
        got,
        Upstream::Claimed(UpstreamClaim {
            run_id: Some("run-42".into()),
            actor: Some("alice@example.com".into()),
        })
    );
}

#[test]
fn sso_session_headers_are_ignored() {
    let map = headers(&[
        (&RUN_ID_HEADER, "run-42"),
        (&ON_BEHALF_OF_HEADER, "mallory"),
    ]);
    let got = from_headers(&map, &identity(IdentityKind::Sso), None);
    assert_eq!(got, Upstream::Absent);
}

#[test]
fn no_headers_is_absent_unless_required() {
    let service = identity(IdentityKind::Service);
    assert_eq!(
        from_headers(&HeaderMap::new(), &service, Some(&policy(false))),
        Upstream::Absent
    );
    assert_eq!(
        from_headers(&HeaderMap::new(), &service, Some(&policy(true))),
        Upstream::Rejected(UPSTREAM_REQUIRED)
    );
    let run_only = headers(&[(&RUN_ID_HEADER, "run-42")]);
    assert_eq!(
        from_headers(&run_only, &service, Some(&policy(true))),
        Upstream::Rejected(UPSTREAM_REQUIRED)
    );
}

#[test]
fn malformed_values_are_rejected() {
    let service = identity(IdentityKind::Service);
    let overlong = "a".repeat(UPSTREAM_MAX_BYTES + 1);
    for bad in ["", "two words", "semi;colon", "quote\"", overlong.as_str()] {
        let map = headers(&[(&RUN_ID_HEADER, bad)]);
        assert_eq!(
            from_headers(&map, &service, None),
            Upstream::Rejected(MALFORMED_RUN_ID),
            "{bad:?}"
        );
    }
    let repeated = headers(&[(&ON_BEHALF_OF_HEADER, "a"), (&ON_BEHALF_OF_HEADER, "b")]);
    assert_eq!(
        from_headers(&repeated, &service, None),
        Upstream::Rejected(MALFORMED_ON_BEHALF_OF)
    );
}

#[test]
fn value_at_the_cap_is_accepted() {
    let at_cap = "a".repeat(UPSTREAM_MAX_BYTES);
    let map = headers(&[(&RUN_ID_HEADER, at_cap.as_str())]);
    let got = from_headers(&map, &identity(IdentityKind::Service), None);
    assert_eq!(got.run_id(), Some(at_cap.as_str()));
}
