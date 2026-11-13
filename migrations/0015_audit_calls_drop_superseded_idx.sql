-- Drop the two `audit_calls` indexes no query reads (plan 101, 03 step 2).
--
-- `audit_calls_user_sub_idx (user_sub)` is a strict prefix of
-- `audit_calls_user_occurred_idx` (0003) and of `audit_calls_history_idx`
-- (0011); `audit_calls_db_type_idx` (0007) served an operator query no code
-- runs. Each only costs the synchronous audit insert. Both clusters run code
-- that reads 0011 before this ships.
--
-- Not CONCURRENTLY: production `audit_calls` is small (plan 101,
-- 01-live-baseline), so the drop lock is momentary.

DROP INDEX audit_calls_user_sub_idx;
DROP INDEX audit_calls_db_type_idx;
