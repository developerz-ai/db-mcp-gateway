-- Synchronous audit trail for the admin API (#51).
-- Spec: docs/initial-idea/12-dynamic-permissions.md §"permissions_audit table".
-- Mirrors the query-audit invariant from CLAUDE.md non-negotiable #4: the
-- writer is synchronous on the request path, and a failed audit write fails
-- the request — admin endpoints (#52..#54) MUST roll back the data change
-- in that case.
--
-- `action` and `target_type` are TEXT-with-CHECK rather than Postgres enums
-- so adding a value is a small ALTER, not a type redefinition. Matches the
-- choice in migrations 0002 and 0004.
--
-- Never logged here: target-DB connection strings, role passwords, role
-- secrets. The audited rows live in `permissions_users` / `permissions_databases`
-- / `permissions_grants` (#47) — none of which store credentials by design
-- (the DSN stays in YAML/secrets). Writers therefore can't accidentally
-- include a secret in the `before`/`after` payload.

CREATE TABLE permissions_audit (
    id           BIGSERIAL   PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     UUID        NOT NULL,
    actor_email  TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    target_type  TEXT        NOT NULL,
    target_id    UUID        NOT NULL,
    -- `before` is NULL on a `create` (no prior state).
    before       JSONB,
    -- `after` is NULL on a `delete` (no post state — soft-delete already
    -- recorded via the target row's timestamp).
    after        JSONB,
    -- Threads the per-request id from spec 07 so a permission change can be
    -- joined back to its origin in operator dashboards.
    request_id   TEXT        NOT NULL,

    CONSTRAINT permissions_audit_action_check
        CHECK (action IN ('create', 'update', 'delete')),

    CONSTRAINT permissions_audit_target_type_check
        CHECK (target_type IN ('user', 'database', 'grant'))
);

-- Operator queries from spec 12: "show me the timeline of all changes",
-- "what did this admin touch", "what happened to this user/database/grant".
CREATE INDEX permissions_audit_ts_idx
    ON permissions_audit (ts);
CREATE INDEX permissions_audit_actor_ts_idx
    ON permissions_audit (actor_id, ts);
CREATE INDEX permissions_audit_target_idx
    ON permissions_audit (target_type, target_id, ts);
