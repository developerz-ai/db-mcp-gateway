-- Two-phase audit (spec 07 §"Intent and completion"). The gateway inserts an
-- intent row here before any call reaches a target database, and the usual
-- `audit_calls` row after it. An intent with no `audit_calls` row of the same
-- `request_id` means the gateway died between the two writes; the reaper
-- (`src/audit/reaper.rs`) turns it into an `outcome = 'abandoned'` row.
--
-- Carries what the reaper needs to build that row (`audit_calls.user_email`
-- is NOT NULL). No FK to `audit_calls`: both tables are append-only with
-- independent retention deletes. `access` records whether the call could
-- write, so an abandoned write is visibly one that may have committed.

CREATE TABLE audit_call_intents (
    request_id    TEXT        PRIMARY KEY,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_sub      TEXT        NOT NULL,
    user_email    TEXT        NOT NULL,
    tool          TEXT        NOT NULL,
    server_name   TEXT        NOT NULL,
    database_name TEXT        NOT NULL,
    db_type       TEXT,
    access        TEXT        NOT NULL CHECK (access IN ('read', 'write'))
);

-- The reaper's scan and the retention pruner's delete are both ranges on
-- `occurred_at`.
CREATE INDEX audit_call_intents_occurred_at_idx ON audit_call_intents (occurred_at);
