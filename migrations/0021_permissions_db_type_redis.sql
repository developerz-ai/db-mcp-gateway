-- Redis targets can be registered in the permissions store. `db_type` names
-- the *target* engine a `permissions_databases` row points at (`redis` covers
-- every RESP server: Redis, Dragonfly, Valkey, KeyDB). Widening the CHECK is
-- additive: every existing row already satisfies it.
ALTER TABLE permissions_databases
    DROP CONSTRAINT permissions_databases_db_type_check,
    ADD CONSTRAINT permissions_databases_db_type_check
        CHECK (db_type IN ('postgres', 'mysql', 'mongo', 'redis'));
