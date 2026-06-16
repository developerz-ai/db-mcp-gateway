-- Add CHECK constraints to enforce before/after JSONB nullability invariants (#51).
-- Mirrors the spec in 12-dynamic-permissions.md §"permissions_audit table":
-- - create: before is NULL (no prior state), after is NOT NULL
-- - delete: before is NOT NULL, after is NULL (soft-delete state already recorded)
-- - update: both before and after are NOT NULL
--
-- These constraints prevent invalid audit records from being inserted via raw SQL
-- or admin backfills.

ALTER TABLE permissions_audit
    ADD CONSTRAINT permissions_audit_create_before_null_after_not_null
        CHECK (action != 'create' OR (before IS NULL AND after IS NOT NULL)),
    ADD CONSTRAINT permissions_audit_delete_before_not_null_after_null
        CHECK (action != 'delete' OR (before IS NOT NULL AND after IS NULL)),
    ADD CONSTRAINT permissions_audit_update_before_after_not_null
        CHECK (action != 'update' OR (before IS NOT NULL AND after IS NOT NULL));
