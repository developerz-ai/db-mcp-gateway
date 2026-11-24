-- `get_query_history`'s `sql_sha256` filter hashed the stored `sql` of every
-- row in the caller's (server, database) history to find the matches, so a
-- lookup for an absent or rare hash scanned the whole history whatever the
-- `LIMIT`. The digest is now a column the next migration indexes.
--
-- The state DB computes it: a BEFORE INSERT trigger sets it from the row's
-- stored `sql`, overwriting anything a writer sent, so every insert path —
-- the completion row, the reaper's `abandoned` row, release N-1 during a
-- rollout — carries a digest that matches its statement. Existing rows are
-- backfilled here; only the derived column is written, never a recorded
-- value. NULL exactly when `sql` is NULL.
--
-- Additive: release N-1 neither reads nor writes the column and keeps
-- hashing at read time.

ALTER TABLE audit_calls
    ADD COLUMN sql_sha256 BYTEA;

CREATE FUNCTION audit_calls_set_sql_sha256() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.sql_sha256 := sha256(convert_to(NEW.sql, 'UTF8'));
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_calls_sql_sha256
    BEFORE INSERT ON audit_calls
    FOR EACH ROW EXECUTE FUNCTION audit_calls_set_sql_sha256();

UPDATE audit_calls
    SET sql_sha256 = sha256(convert_to(sql, 'UTF8'))
    WHERE sql IS NOT NULL;
