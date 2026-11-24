-- `run_query` and `explain` take positional `params` bound to `$1..$n`; the
-- statement in `sql` alone no longer says what ran. `params` stores them as
-- the caller sent them: a JSON array, or, when that array's JSON is longer
-- than the gateway's audit byte cap (the one `sql` is cut at), the JSON
-- text's prefix as a JSON string — a string in this column is a cut array.
-- NULL for a call without params, and on the reaper's `abandoned` rows: the
-- intent does not carry them.
--
-- Additive only; release N-1 inserts without it and its rows keep NULL.

ALTER TABLE audit_calls
    ADD COLUMN params JSONB;
