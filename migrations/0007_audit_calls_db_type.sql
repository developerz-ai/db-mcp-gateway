-- Add `db_type` column to `audit_calls` so operator queries can split mongo
-- from postgres at the audit-log layer. Spec 12 §"Mongo adapter" line 241
-- requires this in the audit envelope; #58 wires the writer.
--
-- Nullable: existing rows from 0002-0003 (all pg, all pre-#58) stay valid
-- without backfill. New rows always populate it from `server.kind`.
--
-- TEXT (not an enum) for the same reason as `outcome` in 0002 — adding a
-- third adapter (mysql in #59) doesn't require a migration to register
-- the variant.

ALTER TABLE audit_calls
    ADD COLUMN db_type TEXT;

-- Partial index for the operator query "show me all mongo activity" — the
-- predicate keeps the index tiny on installs without any mongo targets.
CREATE INDEX audit_calls_db_type_idx
    ON audit_calls (db_type)
    WHERE db_type IS NOT NULL;
