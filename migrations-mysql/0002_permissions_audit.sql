-- MySQL translation of `migrations/0005_permissions_audit.sql` +
-- `migrations/0006_permissions_audit_before_after_constraints.sql` —
-- collapsed because there are no live mysql installs to retain ordering
-- for. Spec: docs/initial-idea/12-dynamic-permissions.md
-- §"permissions_audit table".

CREATE TABLE permissions_audit (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts           TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    actor_id     CHAR(36)     NOT NULL,
    actor_email  VARCHAR(255) NOT NULL,
    action       VARCHAR(32)  NOT NULL,
    target_type  VARCHAR(32)  NOT NULL,
    target_id    CHAR(36)     NOT NULL,
    -- `before` and `after` follow the same NULL invariants as pg:
    --   create → before NULL, after NOT NULL
    --   update → both NOT NULL
    --   delete → before NOT NULL, after NULL
    -- (CHECK constraints below enforce this on mysql 8.)
    before_json  JSON         NULL,
    after_json   JSON         NULL,
    request_id   VARCHAR(255) NOT NULL,

    CONSTRAINT permissions_audit_action_check
        CHECK (action IN ('create', 'update', 'delete')),
    CONSTRAINT permissions_audit_target_type_check
        CHECK (target_type IN ('user', 'database', 'grant')),
    CONSTRAINT permissions_audit_actor_email_not_empty
        CHECK (CHAR_LENGTH(actor_email) > 0),
    CONSTRAINT permissions_audit_request_id_not_empty
        CHECK (CHAR_LENGTH(request_id) > 0),
    CONSTRAINT permissions_audit_create_before_null_after_not_null
        CHECK (action != 'create' OR (before_json IS NULL AND after_json IS NOT NULL)),
    CONSTRAINT permissions_audit_delete_before_not_null_after_null
        CHECK (action != 'delete' OR (before_json IS NOT NULL AND after_json IS NULL)),
    CONSTRAINT permissions_audit_update_before_after_not_null
        CHECK (action != 'update' OR (before_json IS NOT NULL AND after_json IS NOT NULL)),

    KEY permissions_audit_ts_idx (ts),
    KEY permissions_audit_actor_ts_idx (actor_id, ts),
    KEY permissions_audit_target_idx (target_type, target_id, ts)
);
