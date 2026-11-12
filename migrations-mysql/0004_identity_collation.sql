-- Identity and routing columns compare case- and accent-sensitively (plan 101, slice 07).
--
-- `0001_permissions.sql` took the server default collation
-- (`utf8mb4_0900_ai_ci`): case- and accent-insensitive. An SSO subject is
-- an opaque, case-sensitive string, so under that collation `Alice` and
-- `alice` collided on `permissions_users_user_sub_live_uk` — the second
-- subject's upsert silently updated the first one's row, and the resolver's
-- `WHERE user_sub = ?` returned one subject's grants for the other. The pg
-- store compares `text` exactly.
--
-- `utf8mb4_0900_as_cs` (case- and accent-sensitive, NO PAD) rather than
-- `utf8mb4_bin`: a `_bin` collation makes MySQL flag the column BINARY, which
-- sqlx then decodes as VARBINARY and refuses to read into a `String`; and
-- `utf8mb4_bin` is PAD SPACE, so `alice` and `alice ` would still collide.
--
-- The generated `live_*` columns are re-declared with the same collation so
-- the partial-uniqueness emulation keys on the exact value too. Their unique
-- keys are rebuilt by the MODIFY.

ALTER TABLE permissions_users
    MODIFY user_sub VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY live_user_sub VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs
        GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN user_sub ELSE NULL END) STORED;

ALTER TABLE permissions_databases
    MODIFY server VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY db_name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY live_server VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs
        GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN server ELSE NULL END) STORED,
    MODIFY live_db_name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs
        GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN db_name ELSE NULL END) STORED;

-- A wildcard grant names its server directly; it must match the
-- databases' `server` exactly, not case-folded.
ALTER TABLE permissions_grants
    MODIFY server VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NULL;
