---
description: Add a state-DB or permissions-store migration and prove it applies. Use for migration, migrations, schema, sqlx, audit_calls, permissions table.
applies: [rust]
---

> House skill — written from this repo's own evidence and owned by this repository's maintainers. Correct it in place; setup never overwrites a skill that exists.

1. Know which store you are changing: the gateway's own state DB (sessions, audit log, OAuth clients, permissions) is Postgres and lives in `migrations/`; the MySQL permissions store lives in `migrations-mysql/` with its own numbering. Both are embedded by `sqlx::migrate!` in `src/state/migrate.rs` and applied at boot — a failed migration, or an applied one whose checksum changed, refuses to start the process.
2. Add a new file with the next zero-padded number after the highest one in the directory — `ls migrations/ migrations-mysql/`, never a number copied from a doc. Never edit a migration that has already been applied: its checksum changes and the migrator refuses to run.
3. Expand, then contract. The migrators tolerate versions a newer release applied (`set_ignore_missing`), so release N-1 must run on schema N: add first; drop a column, index or table only in a later migration, after the release that stopped using it runs everywhere (see `migrations/0011_*` → `0015_*`).
4. Write the SQL for the target engine: Postgres 16 for `migrations/`, MySQL 8 for `migrations-mysql/`; keep the existing table names (`audit_calls`, `audit_call_intents`, `permissions_users`, `permissions_databases`, `permissions_grants`, `permissions_audit`). A new `permissions_databases.db_type` value lands in both directories (e.g. `0021_permissions_db_type_redis.sql` and `0006_db_type_redis.sql`).
5. Name indexes the way the existing ones are named (`<table>_<columns>_idx`, e.g. `audit_calls_history_idx`) and add them in their own migration file.
6. Prove it through the queued wrapper, never a raw `cargo test` (it skips the dev-DB lock and races other runs): `bin/test --test it_db migrations_real_db::` applies every migration to a throwaway database, re-runs it as a no-op and checks both migrators boot on a newer schema; add an assertion there for the object you created. Then `bin/test --test it_db <the module that reads it>::`. fail -> "failed to run state DB migrations": paste the statement into `bin/dev psql state` (or `bin/dev mysql`) to see the server's own error.
7. Update the spec in `website/docs/initial-idea/` when the schema change is visible to an operator or an agent — same PR.
