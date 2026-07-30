-- Resolver hot-path indexes missing from `0001_permissions.sql`.
-- Spec: docs/initial-idea/12-dynamic-permissions.md §"Storage backends" —
-- the mysql store must match the pg store semantically *and* operationally.
--
-- `0001` emulated pg's partial UNIQUE indexes with generated `live_*`
-- columns. That covers uniqueness, but not lookup: mysql cannot serve
-- `WHERE user_sub = ?` from an index on the *generated* `live_user_sub`
-- column, so `permissions_users` was full-scanned on every permissions-cache
-- miss (`crate::authz::loader::load_db_grants_for`). Pg gets the lookup for
-- free because its partial index is on the base column.
--
-- Measured on 50k users / 20k databases (mysql 8):
--   users     ALL, 49690 rows examined, 41.1 ms -> ref, 1 row, 0.06 ms
--   databases ALL + filesort, 19501 rows       -> ref, no filesort
--
-- Convention follows the grants indexes in `0001`: plain composite
-- `(lookup_col, soft_delete_ts)` rather than an index on the generated
-- column. The generated-column trick exists only to emulate partial
-- *uniqueness*; the repo layer always filters on the real `deleted_at` /
-- `revoked_at` columns, keeping the mysql SQL a 1:1 translation of the pg
-- SQL (see `crate::state::permissions::mysql`).

-- `get_user_by_sub`: `WHERE user_sub = ? AND deleted_at IS NULL`.
-- Non-unique on purpose — soft-deleted rows repeat a `user_sub`, and a
-- second UNIQUE key here would also change which conflicts
-- `ON DUPLICATE KEY UPDATE` fires on in `upsert_user`. Uniqueness stays
-- solely with `permissions_users_user_sub_live_uk`.
ALTER TABLE permissions_users
    ADD KEY permissions_users_user_sub_live_idx (user_sub, deleted_at);

-- `list_databases`: `WHERE deleted_at IS NULL ORDER BY server, db_name`.
-- `deleted_at` leads (it is the only filter); the trailing columns then
-- supply the sort order, so the filesort drops. Column order therefore
-- differs from the users index above, which leads with its equality column.
ALTER TABLE permissions_databases
    ADD KEY permissions_databases_server_db_name_live_idx (deleted_at, server, db_name);
