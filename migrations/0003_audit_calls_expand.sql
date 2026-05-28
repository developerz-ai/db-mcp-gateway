-- Expand `audit_calls` per spec doc 07 (issue #8). The minimal schema from
-- 0002 captured tool + outcome; spec wants the group snapshot + reason +
-- per-call result/error metadata so operators can run the queries shown in
-- spec 07 §"Operator queries".
--
-- All additions are nullable: existing rows from 0002 stay valid, and tools
-- without a value (e.g. `list_servers` has no `row_count`) leave them NULL.

ALTER TABLE audit_calls
    ADD COLUMN groups        JSONB,
    ADD COLUMN reason        TEXT,
    ADD COLUMN row_count     BIGINT,
    ADD COLUMN truncated     BOOLEAN,
    ADD COLUMN error_message TEXT,
    ADD COLUMN agent_client  TEXT,
    -- IP stored as TEXT (formatted via Rust's `IpAddr::to_string`) so we
    -- don't need to enable sqlx's `ipnetwork` feature. Operators querying
    -- the table can still pattern-match (`ip LIKE '10.%'`); the few queries
    -- that need true CIDR semantics can `ip::inet` cast at read time.
    ADD COLUMN ip            TEXT;

-- Composite index for the common operator query: "who did what in the last
-- hour" (filter by user, ordered by time). The standalone occurred_at idx
-- from 0001 stays for whole-system time-range queries.
CREATE INDEX audit_calls_user_occurred_idx ON audit_calls (user_sub, occurred_at DESC);
