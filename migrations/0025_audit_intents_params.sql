-- `run_query` and `explain` bind positional `params` (0024 stores them on the
-- completion row). An intent carried only the statement, so a parameterized
-- write that committed before the gateway stopped left an `abandoned` row
-- with placeholders and no values: no record of what it changed. The intent
-- now carries the params, capped exactly as `audit_calls.params` is (a JSON
-- array, or the cut prefix of its JSON text as a JSON string), and the
-- reaper copies them.
--
-- Additive only; release N-1 inserts without it and its rows keep NULL.

ALTER TABLE audit_call_intents
    ADD COLUMN params JSONB;
