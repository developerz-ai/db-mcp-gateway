-- Mongo targets can be registered in the permissions store (plan 101, slice 07).
-- `db_type` names the *target* engine a `permissions_databases` row points at;
-- `0004_permissions.sql` listed only the SQL engines, so a Mongo server
-- declared in config could not carry DB-backed grants. Widening the CHECK is
-- additive: every existing row already satisfies it.
ALTER TABLE permissions_databases
    DROP CONSTRAINT permissions_databases_db_type_check,
    ADD CONSTRAINT permissions_databases_db_type_check
        CHECK (db_type IN ('postgres', 'mysql', 'mongo'));
