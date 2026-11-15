-- Store parity with `migrations/0021_permissions_db_type_redis.sql`: a
-- `permissions_databases` row may register a RESP target (Redis, Valkey,
-- Dragonfly).
ALTER TABLE permissions_databases
    DROP CHECK permissions_databases_db_type_check,
    ADD CONSTRAINT permissions_databases_db_type_check
        CHECK (db_type IN ('postgres', 'mysql', 'mongo', 'redis'));
