---
description: Add a state-DB or permissions-store migration and prove it applies. Use for migration, migrations, schema, sqlx, audit_calls, permissions table.
applies: [rust]
---

> House skill — written from this repo's own evidence and owned by this repository's maintainers. Correct it in place; setup never overwrites a skill that exists.

1. Know which store you are changing: the gateway's own state DB (sessions, audit log, OAuth clients, permissions) is Postgres and lives in `migrations/`; the MySQL permissions store lives in `migrations-mysql/` with its own numbering. Both are embedded by `sqlx::migrate!` in `src/state/mod.rs` and applied at boot — a failing migration refuses to start the process.
2. Add a new file with the next zero-padded number: `migrations/0010_<name>.sql` (existing: 0001_sessions.sql … 0009_oauth_refresh_tokens.sql) or `migrations-mysql/0004_<name>.sql` (existing: 0001_permissions.sql … 0003_permissions_resolver_indexes.sql). Never edit a migration that has already been applied — its checksum changes and the migrator refuses to run.
3. Write the SQL for the target engine: Postgres 16 for `migrations/`, MySQL 8 for `migrations-mysql/`; keep the existing table names (`audit_calls`, `permissions`, `permissions_audit`).
4. Prove it on an empty database: `bin/dev reset` (removes the volumes), `bin/dev up`, then `bin/test` — the integration tests boot the gateway against the dev state DB and apply the pending migrations. fail -> "failed to run state DB migrations" means the statement was rejected; copy it into `bin/dev psql state` to see the server's own error.
5. Name indexes the way the existing ones are named (e.g. `audit_calls_user_occurred_idx` from migration 0003) and add them in their own migration file.
6. Update the spec in `website/docs/initial-idea/` when the schema change is visible to an operator or an agent — same PR.
