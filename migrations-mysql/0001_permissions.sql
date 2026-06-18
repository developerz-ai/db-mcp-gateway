-- MySQL translation of `migrations/0004_permissions.sql` (#59).
-- Spec: docs/initial-idea/12-dynamic-permissions.md §"Storage backends".
-- Schema MUST match the pg version semantically — the resolver reads
-- through [`crate::state::permissions::PermissionsRepo`], so any
-- divergence in column meaning would silently change auth decisions.
--
-- Translation rules applied:
--   - JSONB    → JSON              (mysql 5.7+; equivalent storage)
--   - TIMESTAMPTZ → TIMESTAMP(6)   (mysql stores TIMESTAMP in UTC; (6) keeps
--                                   microsecond precision so update ordering
--                                   matches pg's behavior)
--   - gen_random_uuid() default → no default; the repo passes a Rust-side
--     `Uuid::new_v4()` per spec 12's "the repo, not the DB, mints IDs".
--   - Partial UNIQUE index (`WHERE deleted_at IS NULL`) → emulated via a
--     generated `live_key` column + plain UNIQUE on it.
--   - BIGSERIAL → BIGINT AUTO_INCREMENT (mysql equivalent for the audit id)
--   - CHECK constraints: mysql 8 enforces them; on 5.7 they're parsed-only.
--     We keep them so the schema reads correctly and rely on the repo's
--     validator (`db_type` / `action` enums parse from strings) as the
--     real safety net.

CREATE TABLE permissions_users (
    id          CHAR(36)      PRIMARY KEY,
    user_sub    VARCHAR(255)  NOT NULL,
    user_email  VARCHAR(255)  NOT NULL,
    groups_json JSON          NOT NULL,
    created_at  TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at  TIMESTAMP(6)  NULL,
    -- `live_key = user_sub` for live rows, NULL for soft-deleted rows.
    -- A NULL value in a UNIQUE column does NOT violate the constraint in
    -- mysql, so multiple deleted rows for the same sub coexist. This
    -- emulates pg's `WHERE deleted_at IS NULL` partial index.
    live_user_sub VARCHAR(255) GENERATED ALWAYS AS (
        CASE WHEN deleted_at IS NULL THEN user_sub ELSE NULL END
    ) STORED,
    UNIQUE KEY permissions_users_user_sub_live_uk (live_user_sub)
);

CREATE TABLE permissions_databases (
    id          CHAR(36)      PRIMARY KEY,
    server      VARCHAR(255)  NOT NULL,
    db_name     VARCHAR(255)  NOT NULL,
    db_type     VARCHAR(32)   NOT NULL,
    created_at  TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at  TIMESTAMP(6)  NULL,
    live_server VARCHAR(255) GENERATED ALWAYS AS (
        CASE WHEN deleted_at IS NULL THEN server ELSE NULL END
    ) STORED,
    live_db_name VARCHAR(255) GENERATED ALWAYS AS (
        CASE WHEN deleted_at IS NULL THEN db_name ELSE NULL END
    ) STORED,
    UNIQUE KEY permissions_databases_live_uk (live_server, live_db_name),
    CONSTRAINT permissions_databases_db_type_check
        CHECK (db_type IN ('postgres', 'mysql'))
);

CREATE TABLE permissions_grants (
    id                CHAR(36)      PRIMARY KEY,
    user_id           CHAR(36)      NOT NULL,
    server            VARCHAR(255)  NULL,
    database_id       CHAR(36)      NULL,
    db_name_wildcard  BOOLEAN       NOT NULL DEFAULT FALSE,
    action            VARCHAR(32)   NOT NULL,
    constraints_json  JSON          NOT NULL,
    created_at        TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at        TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at        TIMESTAMP(6)  NULL,

    CONSTRAINT permissions_grants_user_fk
        FOREIGN KEY (user_id) REFERENCES permissions_users(id),
    CONSTRAINT permissions_grants_database_fk
        FOREIGN KEY (database_id) REFERENCES permissions_databases(id),
    CONSTRAINT permissions_grants_action_check
        CHECK (action IN ('schema_read', 'query_read', 'query_write', 'history_read')),
    CONSTRAINT permissions_grants_target_xor_wildcard_check
        CHECK (
            (database_id IS NOT NULL AND db_name_wildcard = FALSE AND server IS NULL)
            OR
            (database_id IS NULL     AND db_name_wildcard = TRUE  AND server IS NOT NULL)
        ),

    -- Plain composite indexes on (user_id, revoked_at) and
    -- (database_id, revoked_at). MySQL has no partial-index support
    -- (`WHERE revoked_at IS NULL`), so unlike pg these include both live
    -- and revoked rows. Queries filtering `revoked_at IS NULL` still use
    -- the index — just with lower selectivity than pg's partial index.
    -- Acceptable: the revoked-row tail is small in practice and the
    -- generated-column trick used for UNIQUE above doesn't help here
    -- (we need range scans on user_id/database_id, not uniqueness).
    KEY permissions_grants_user_live_idx (user_id, revoked_at),
    KEY permissions_grants_database_live_idx (database_id, revoked_at)
);
