# 03 — State-DB migrations

> Part of [`overview.md`](overview.md). Depends on: 02. Ships **before** the code slices that read each object (04, 07, 08, 09, 12).

All state-DB schema changes for the plan, in one place. One migration file per row; each lands in the PR of the slice that first reads it, but numbering is fixed here so parallel slices do not collide. Use the `state-migrations` skill.

## Files to change

| Migration | Object | Read by | Why |
|---|---|---|---|
| `migrations/0010_audit_call_intents.sql` | new table `audit_call_intents (request_id pk, occurred_at, user_sub, tool, server_name, database_name, access)` + index on `occurred_at` | 04 | Two-phase audit: intent row before the target query; reaper finds intents with no `audit_calls` row |
| `migrations/0011_audit_calls_history_idx.sql` | add `(user_sub, server_name, database_name, occurred_at DESC)`; drop `audit_calls_user_sub_idx`; drop `audit_calls_db_type_idx` | 04 | History WHERE is not covered (`src/audit/mod.rs:237-239` vs `migrations/0002:25`); two indexes only cost the synchronous insert |
| `migrations/0012_refresh_tokens_session_id.sql` | `oauth_refresh_tokens.session_id` nullable FK → `sessions(id)` | 08 | Rotation and `/revoke` must kill the paired access session |
| `migrations/0013_permissions_db_type_mongo.sql` | extend `permissions_databases.db_type` CHECK with `mongo` (`migrations/0004:45-46`) | 07 | Mongo targets cannot be registered today |
| `migrations/0014_audit_upstream_identity.sql` | `audit_calls.upstream_actor text`, `upstream_run_id text`, `rows_affected bigint`, `sql_truncated bool not null default false`; same two upstream columns on `audit_call_intents` | 12 | Headless agents share one service identity; rows must carry the claimed task/run and requester |
| `migrations/0015_audit_calls_drop_superseded_idx.sql` | drop `audit_calls_user_sub_idx`, `audit_calls_db_type_idx` (moved out of 0011, which stayed additive) | 04 | Prefix of the 0003/0011 indexes; no query reads `db_type` |
| `migrations/0016_sessions_drop_agent_client.sql` | drop dead column `sessions.agent_client`; shipped after 2.0.2 (code stopped writing it) ran in both clusters (D1 at `sha-cf9701b`, D2 on 2.0.2). `sessions_expires_at_idx` stays: the GC `DELETE … WHERE expires_at < …` reads it (`src/state/sessions.rs` `delete_expired`) | 08 | Always-NULL column (`migrations/0001:18`) |
| `migrations-mysql/0004_identity_collation.sql` | `utf8mb4_bin` on `user_sub`, `live_user_sub`, `server`, `db_name` and live columns | 07 | Case-insensitive default collation merges `Alice`/`alice` (`migrations-mysql/0001:22-37`) |
| `migrations-mysql/0005_db_type_mongo.sql` | same CHECK change as 0013 | 07 | Store parity |

## Steps

1. Confirm the highest existing numbers (`ls migrations migrations-mysql`) before creating files; renumber here if `main` moved.
2. Each migration is additive or index-only except 0015 and 0016 (drops). Drops go in their own PR **after** the code that stopped depending on them is deployed in both clusters (slices 14, 15).
3. Build large indexes `CONCURRENTLY` — requires `-- no-transaction` at the top of the sqlx migration file. 01 gives `audit_calls` row counts per cluster; skip `CONCURRENTLY` only if both are small.
4. `audit_call_intents` is pruned by the audit pruner (10) on the same retention as `audit_calls`; no FK between the two (append-only, independent retention deletes).
5. Do not touch the dead MySQL `permissions_audit` table (`migrations-mysql/0002`); 07 decides its fate.
6. Spec: `website/docs/initial-idea/07-logging-retention.md` — fix table/column names (`audit_calls`, `occurred_at`, `server_name`, `database_name`, outcome `success`, add `cancelled`/`abandoned`), add the new columns.

## Tests

- New `tests/migrations_real_db.rs`: apply all migrations from an empty DB, re-run (idempotent no-op), assert each new object exists (`information_schema`, `pg_indexes`).
- `tests/get_query_history_real_db.rs`: EXPLAIN assertion that the history query uses the 0011 index — model on `tests/permissions_indexes_mysql.rs`.
- `tests/permissions_repo_mysql.rs`: two subjects differing only in case stay distinct (0004).
- `bin/test`, `bin/lint`.

## Done when

- `sqlx migrate` applies cleanly from empty and from the current production schema version.
- No code slice merges ahead of the migration it reads.
- Spec 07 operator queries run verbatim against the real schema.
