-- Retention pruning of dead permissions rows (spec 07 §"Retention pruning").
-- The pruner deletes revoked grants and soft-deleted users/databases older
-- than AUDIT_RETENTION_DAYS, oldest first, in batches; these partial indexes
-- make each batch an index range over the dead rows only.
--
-- The 0004 grant indexes are partial on `revoked_at IS NULL`, so they cannot
-- serve the parent deletes' NOT EXISTS probe or the FK check on a parent
-- delete; the full (user_id) / (database_id) indexes do.
--
-- Not CONCURRENTLY: the permissions tables hold config-scale row counts, so
-- the build lock is momentary.

CREATE INDEX permissions_grants_revoked_at_idx
    ON permissions_grants (revoked_at)
    WHERE revoked_at IS NOT NULL;

CREATE INDEX permissions_users_deleted_at_idx
    ON permissions_users (deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE INDEX permissions_databases_deleted_at_idx
    ON permissions_databases (deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE INDEX permissions_grants_user_id_idx
    ON permissions_grants (user_id);

CREATE INDEX permissions_grants_database_id_idx
    ON permissions_grants (database_id)
    WHERE database_id IS NOT NULL;
