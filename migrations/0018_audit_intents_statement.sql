-- An intent records what is about to run, not only who runs it. Before this,
-- the reaper's `abandoned` row for a call that died between the target and
-- its completion row named the identity and the access but not the statement
-- or the stated reason — a write that may have committed with no record of
-- what it was. The intent now carries the same `sql` (capped at the gateway's
-- audit byte cap, `sql_truncated` when cut) and `reason` the completion row
-- would have, and the reaper copies them.
--
-- Additive only; release N-1 inserts without them and its rows keep NULL.

ALTER TABLE audit_call_intents
    ADD COLUMN sql           TEXT,
    ADD COLUMN sql_truncated BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN reason        TEXT;
