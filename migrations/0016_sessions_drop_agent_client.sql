-- Drop `sessions.agent_client` (plan 101, 03): always NULL, and no code has
-- read or written it since 2.0.2. Both clusters ran 2.0.2 before this ships,
-- so no live replica still inserts the column.
--
-- The per-call client banner stays on `audit_calls.agent_client`.
-- `sessions` holds only live sessions plus an hour of expired ones, so the
-- ACCESS EXCLUSIVE lock is momentary.

ALTER TABLE sessions DROP COLUMN agent_client;
