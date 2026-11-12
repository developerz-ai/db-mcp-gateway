//! `permissions_audit.before` / `.after` shapes — one per entity, shared by
//! every handler that audits it (a user delete audits the grants it
//! cascades too). No credential can appear: the source rows have none.

use serde_json::{Value as JsonValue, json};

use crate::state::permissions::{PermissionsDatabase, PermissionsGrant, PermissionsUser};

pub(super) fn user_payload(u: &PermissionsUser) -> JsonValue {
    json!({
        "id": u.id,
        "user_sub": u.user_sub,
        "user_email": u.user_email,
        "groups": u.groups,
        "created_at": u.created_at,
        "updated_at": u.updated_at,
    })
}

pub(super) fn database_payload(d: &PermissionsDatabase) -> JsonValue {
    json!({
        "id": d.id,
        "server": d.server,
        "db_name": d.db_name,
        "db_type": d.db_type.as_db_str(),
        "created_at": d.created_at,
        "updated_at": d.updated_at,
    })
}

pub(super) fn grant_payload(g: &PermissionsGrant) -> JsonValue {
    let (server, database_id, wildcard) = g.target.columns();
    json!({
        "id": g.id,
        "user_id": g.user_id,
        "database_id": database_id,
        "server": server,
        "db_name_wildcard": wildcard,
        "action": g.action.as_db_str(),
        "constraints": g.constraints,
        "created_at": g.created_at,
        "updated_at": g.updated_at,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn user_payload_serializes_expected_shape() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let user = PermissionsUser {
            id: Uuid::nil(),
            user_sub: "sub-123".into(),
            user_email: "a@example.com".into(),
            groups: vec!["engineers".into()],
            created_at: ts,
            updated_at: ts,
            deleted_at: None,
        };
        let payload = user_payload(&user);
        assert_eq!(payload["id"], json!(Uuid::nil()));
        assert_eq!(payload["user_sub"], "sub-123");
        assert_eq!(payload["user_email"], "a@example.com");
        assert_eq!(payload["groups"], json!(["engineers"]));
        assert_eq!(payload["created_at"], json!(ts));
        assert_eq!(payload["updated_at"], json!(ts));
        // Storage-only field must not widen the admin payload.
        assert!(payload.get("deleted_at").is_none());
    }
}
