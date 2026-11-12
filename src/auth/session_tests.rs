use super::*;

fn base_session() -> Session {
    Session {
        id: SessionId::new(),
        user_sub: "sub".into(),
        user_email: "e@example.com".into(),
        groups: vec!["a".into(), "b".into()],
        agent_client: Some("claude-code/0.x".into()),
        issued_at: Utc::now(),
        expires_at: Utc::now() + ChronoDuration::hours(1),
        revoked_at: None,
    }
}

#[test]
fn identity_clone_carries_fields() {
    let identity = base_session().identity();
    assert_eq!(identity.user_sub, "sub");
    assert_eq!(identity.groups, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn revoked_or_expired_is_inactive() {
    let now = Utc::now();
    let base = base_session();
    assert!(base.is_active(now));
    let revoked = Session {
        revoked_at: Some(now),
        ..base.clone()
    };
    assert!(!revoked.is_active(now));
    let expired = Session {
        issued_at: now - ChronoDuration::hours(2),
        expires_at: now - ChronoDuration::seconds(1),
        ..base
    };
    assert!(!expired.is_active(now));
}
