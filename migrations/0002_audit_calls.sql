-- Audit log of every tool call that traces to a target-DB action.
-- Spec: docs/initial-idea/07-logging-retention.md (retention/archive/sinks
-- land with #8). The write is synchronous on the request path — a failed
-- audit write fails the request (CLAUDE.md non-negotiable).
--
-- `outcome` is the union of "success" and the spec 03 error codes a tool can
-- surface (`forbidden`, `timeout`, `syntax_error`, `unavailable`,
-- `reason_required`, `internal`). Kept as TEXT (not an enum) so adding codes
-- in later issues doesn't require a migration.

CREATE TABLE audit_calls (
    id          UUID        PRIMARY KEY,
    request_id  TEXT        NOT NULL,
    user_sub    TEXT        NOT NULL,
    user_email  TEXT        NOT NULL,
    tool        TEXT        NOT NULL,
    server_name TEXT,
    database_name TEXT,
    sql         TEXT,
    outcome     TEXT        NOT NULL,
    elapsed_ms  BIGINT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_calls_user_sub_idx    ON audit_calls (user_sub);
CREATE INDEX audit_calls_occurred_at_idx ON audit_calls (occurred_at);
CREATE INDEX audit_calls_request_id_idx  ON audit_calls (request_id);
