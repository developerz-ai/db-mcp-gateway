-- Headless agents share one service identity (spec 14), so a row needs the
-- task/run and the requester the agent CLAIMED for the call
-- (`x-dbmcp-run-id`, `x-dbmcp-on-behalf-of`). Both are unverified: stored for
-- attribution, never used for authz. NULL for SSO sessions, whose identity is
-- verified (plan 101, slice 12 step 2).
--
-- `rows_affected`: rows a write (or a rolled-back `dry_run`) changed; NULL for
-- reads. `sql_truncated`: the stored `sql` was cut at the gateway's byte cap
-- (plan 101, slice 04 step 8).
--
-- Additive only; every existing row satisfies the defaults.

ALTER TABLE audit_calls
    ADD COLUMN upstream_actor  TEXT,
    ADD COLUMN upstream_run_id TEXT,
    ADD COLUMN rows_affected   BIGINT,
    ADD COLUMN sql_truncated   BOOLEAN NOT NULL DEFAULT false;

-- The reaper copies these into the `abandoned` row it builds.
ALTER TABLE audit_call_intents
    ADD COLUMN upstream_actor  TEXT,
    ADD COLUMN upstream_run_id TEXT;
