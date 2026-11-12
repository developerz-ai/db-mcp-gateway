-- `get_query_history` filters on (user_sub, server_name, database_name) and
-- pages by keyset on (occurred_at, id), newest first. The 0003 index
-- (user_sub, occurred_at DESC) covers the user and the order but leaves the
-- server/database filter to a heap recheck of every row the user owns.
--
-- Additive only. The indexes this one supersedes (`audit_calls_user_sub_idx`,
-- `audit_calls_db_type_idx`) are dropped by a later migration, after this
-- code is deployed in both clusters (plan 101, 03 step 2).
--
-- Not CONCURRENTLY: production `audit_calls` holds tens of rows (plan 101,
-- 01-live-baseline), so the build lock is momentary.

CREATE INDEX audit_calls_history_idx
    ON audit_calls (user_sub, server_name, database_name, occurred_at DESC, id DESC);
