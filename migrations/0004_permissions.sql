-- DB-backed permissions store (spec: docs/initial-idea/12-dynamic-permissions.md,
-- issue #47). Lives alongside YAML grants — the resolver merges both sources
-- through the existing constraint-merge engine. Most-restrictive value wins;
-- neither source has priority.
--
-- Three tables: `users` (registered SSO identities), `databases` (logical
-- targets), `grants` (the access mapping). All writes go through the admin
-- API (#52..#54), which audits to `permissions_audit` (#51) synchronously.
--
-- `db_type` and `action` are TEXT-with-CHECK rather than Postgres enums so
-- adding a value is a small ALTER, not a type redefinition; the CHECK keeps
-- illegal values out today.

-- Users registered for runtime permissions. The SSO subject is the identity;
-- email + groups are denormalized caches refreshed on login (the JWT is the
-- live source of truth — this is just for joins and the admin API listing).
CREATE TABLE permissions_users (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub    TEXT        NOT NULL,
    user_email  TEXT        NOT NULL,
    groups      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);

-- Partial unique index: a soft-deleted user can be re-registered with the
-- same SSO subject. Plain UNIQUE would block re-onboarding.
CREATE UNIQUE INDEX permissions_users_user_sub_live_idx
    ON permissions_users (user_sub)
    WHERE deleted_at IS NULL;

-- Logical database references that grants attach to. The connection string
-- itself never lives here — it stays in YAML/secrets per CLAUDE.md
-- non-negotiable #1. This row carries only the routing key.
CREATE TABLE permissions_databases (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    server      TEXT        NOT NULL,
    db_name     TEXT        NOT NULL,
    db_type     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,

    CONSTRAINT permissions_databases_db_type_check
        CHECK (db_type IN ('postgres', 'mysql'))
);

CREATE UNIQUE INDEX permissions_databases_server_db_name_live_idx
    ON permissions_databases (server, db_name)
    WHERE deleted_at IS NULL;

-- The access mapping. Either points at a specific database row OR is a
-- wildcard (`db_name = "*"` in spec 12 §Wildcard) — the CHECK enforces that
-- pairing so the resolver never has to reconcile the two flags. Wildcards
-- are for dev/superuser grants; constraints still apply, most-restrictive
-- still wins on overlap with a more-specific grant.
CREATE TABLE permissions_grants (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID        NOT NULL REFERENCES permissions_users(id),
    server            TEXT,
    database_id       UUID        REFERENCES permissions_databases(id),
    db_name_wildcard  BOOLEAN     NOT NULL DEFAULT false,
    action            TEXT        NOT NULL,
    constraints       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,

    CONSTRAINT permissions_grants_action_check
        CHECK (action IN ('schema_read', 'query_read', 'query_write', 'history_read')),

    CONSTRAINT permissions_grants_target_xor_wildcard_check
        CHECK (
            (database_id IS NOT NULL AND db_name_wildcard = false AND server IS NULL)
            OR
            (database_id IS NULL     AND db_name_wildcard = true AND server IS NOT NULL)
        )
);

-- Resolver lookup path: every tool call asks "live grants for this user".
-- Partial index on live rows keeps it tight even as revoked grants accumulate.
CREATE INDEX permissions_grants_user_live_idx
    ON permissions_grants (user_id)
    WHERE revoked_at IS NULL;

-- Admin API listing path: "show all grants on this database".
CREATE INDEX permissions_grants_database_live_idx
    ON permissions_grants (database_id)
    WHERE revoked_at IS NULL AND database_id IS NOT NULL;
