-- Store parity with `migrations/0013_permissions_db_type_mongo.sql`: a
-- `permissions_databases` row may register a Mongo target.
ALTER TABLE permissions_databases
    DROP CHECK permissions_databases_db_type_check,
    ADD CONSTRAINT permissions_databases_db_type_check
        CHECK (db_type IN ('postgres', 'mysql', 'mongo'));
