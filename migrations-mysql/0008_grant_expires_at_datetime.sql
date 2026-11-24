-- `0007` made `expires_at` a TIMESTAMP(6), whose range ends 2038-01-19: a
-- grant expiring later was rejected here while Postgres stored it. DATETIME(6)
-- holds any year; the gateway reads and writes it as UTC. A new migration
-- rather than an edit of `0007`: a store that already applied it would refuse
-- to boot on the changed checksum.
--
-- The conversion reads each TIMESTAMP in the session time zone, which sqlx
-- pins to `+00:00`, so existing expiries keep their UTC instant. The column
-- holds only NULLs before any grant sets an expiry.
ALTER TABLE permissions_grants
    MODIFY COLUMN expires_at DATETIME(6) NULL;
