# Operations

Backup, restore, upgrade and rollback. The gateway itself is stateless: everything durable is in the **state DB** (Postgres) and, with `permissions_store.driver: mysql`, the MySQL permissions store. The YAML config lives in your git repository.

## What lives where

| Store | Tables | Losing it means |
|---|---|---|
| State DB | `audit_calls`, `audit_call_intents` | The audit trail since the last backup |
| State DB | `sessions`, `oauth_refresh_tokens`, `oauth_refresh_rotated`, `oauth_clients` | Everyone signs in again; MCP clients re-register |
| State DB (default) or MySQL | `permissions_users`, `permissions_databases`, `permissions_grants`, `permissions_audit` | Grants made through the admin API, and their history. YAML grants are unaffected |
| State DB | `_sqlx_migrations` | Must travel with the schema it describes — never edit it |
| Config repo | `config.yml` | Rebuild from git |
| Your secret manager | DB passwords, `SESSION_SIGNING_KEY`, `OIDC_CLIENT_SECRET`, service tokens | Re-issue them |

## State DB roles

The audit tables are append-only by convention: the gateway never issues an `UPDATE` against `audit_calls`, `audit_call_intents` or `permissions_audit`. To have Postgres enforce that, run the gateway under a role that does not own the schema:

| Role | Used by | Audit tables |
|---|---|---|
| `gateway_owner` | Migrations only — owns the database, the schema and every table | everything (owner) |
| `gateway_app` | `STATE_DB_URL` at runtime | `SELECT`, `INSERT`, `DELETE` (no `UPDATE`, no `TRUNCATE`) |

1. Create both roles (`CREATE ROLE … LOGIN PASSWORD …`), and the database with `OWNER gateway_owner`.
2. Apply the migrations as `gateway_owner`: boot the gateway once with `STATE_DB_URL` pointing at `gateway_owner` and stop it once `/readyz` answers, or run `sqlx migrate run --source migrations` from the release tag's checkout. For `sqlx`, put the password in the libpq password file (see [Credentials for the tools below](#credentials-for-the-tools-below)) and pass a URL without one: `--database-url postgres://gateway_owner@state-db.internal:5432/gateway`.
3. Run the grants below as `gateway_owner`, then point `STATE_DB_URL` at `gateway_app`.

{/* state-db-role-grants:start */}
```sql
-- CREATE: the migrator runs `CREATE TABLE IF NOT EXISTS _sqlx_migrations` at
-- every boot, even with nothing to apply.
GRANT USAGE, CREATE ON SCHEMA public TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gateway_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gateway_app;
-- Audit trail: append and read. DELETE stays for the built-in retention pruner.
REVOKE UPDATE ON audit_calls, audit_call_intents, permissions_audit FROM gateway_app;
-- Migration history is read-only, so only gateway_owner can migrate.
REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations FROM gateway_app;
```
{/* state-db-role-grants:end */}

`tests/it_db/audit_role_split_real_db.rs` runs this block against a fresh database and checks that `gateway_app` boots, writes audit rows, and runs the pruner and the reaper, and that an `UPDATE` or `TRUNCATE` on `audit_calls` is refused.

**On every upgrade**, apply the new migrations as `gateway_owner` before rolling replicas, then re-run the block: a migration's new tables get no grants until you do. A replica cannot do it for you: one that finds a pending migration under `gateway_app` exits at boot, because recording the migration needs the write on `_sqlx_migrations` revoked above and its DDL needs ownership; nothing is half-applied. The [Upgrade](#upgrade) checklist puts the steps in order.

**What this does not cover.** `gateway_app` keeps `DELETE` on the audit tables, because the retention pruner runs inside the gateway on the same `STATE_DB_URL`. Revoking it fails every hourly prune (`audit_pruner_runs_total{result="error"}`) and nothing ages the rows out. A separate pruner credential, so the runtime role can be insert-only, is not supported yet. Neither is a tamper-evident hash chain over the rows: a role holding `DELETE`, or `gateway_owner`, can still remove rows, so keep `gateway_owner`'s credential out of the gateway's environment and stream rows to an external store (`logging.stream`) if you need a copy the gateway cannot touch.

## Credentials for the tools below

Never put a password on a command line: a `postgres://user:password@…` URL or `mysql -pSECRET` is readable by every local user through `ps` and `/proc`, and lands in shell history. `$STATE_DB_URL` carries the gateway's password, so do not pass it to `pg_dump` either. Give each client a protected password file and pass only non-secret connection arguments:

- **Postgres (libpq: `pg_dump`, `pg_restore`, `psql`, `sqlx`).** One line per credential in `~/.pgpass`, or in the file `PGPASSFILE` names (a mounted secret, for a job), as `host:port:database:user:password`. libpq ignores the file unless it is mode `0600`:

  ```bash
  umask 077
  "$EDITOR" ~/.pgpass                 # state-db.internal:5432:gateway:gateway_owner:<password>
  chmod 600 ~/.pgpass
  ```

- **MySQL (`mysqldump`, `mysql`).** An option file with a `[client]` section (`user=`, `password=`), mode `0600`, passed first as `--defaults-extra-file=/path/backup.cnf`.

## Backup

Back up the state DB like any production Postgres: continuous archiving / PITR if you have it, otherwise a scheduled `pg_dump`, authenticated through the password file above:

```bash
pg_dump --format=custom --no-owner \
  --host=state-db.internal --port=5432 --username=gateway_owner --dbname=gateway \
  --file="gateway-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

- **Retention matches the audit policy.** The gateway prunes rows past `AUDIT_RETENTION_DAYS` (default 90) hourly, but your backups keep whatever they contain for as long as you keep the backups. Set backup retention to the same window, or deliberately longer if compliance wants it ([spec 07](../initial-idea/07-logging-retention.md#retention-surfaces-outside-the-gateway)).
- **Treat dumps as sensitive.** They hold SQL text, reasons and emails, plus session and refresh-token rows. They never hold target DB credentials.
- Take one right before every upgrade — of the state DB **and**, with `permissions_store.driver: mysql`, of the permissions store (below).
- **Roles are not in the dump.** `pg_dump` saves a database; `gateway_owner` and `gateway_app` are cluster-wide. With the [split roles](#state-db-roles), save their definitions beside each dump — without passwords, which stay in your secret manager:

  ```bash
  pg_dumpall --roles-only --no-role-passwords \
    --host=state-db.internal --port=5432 --username=gateway_owner \
    --file="gateway-roles-$(date -u +%Y%m%dT%H%M%SZ).sql"
  ```

  The file lists every role in the cluster; keep the `gateway_owner` and `gateway_app` lines.

### MySQL permissions store

On the same schedule as the state DB, and right before every upgrade (the gateway applies the store's migrations at boot, like the state DB's):

```bash
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mysqldump --defaults-extra-file=/secure/backup.cnf --single-transaction \
  --host=perm-db.internal --port=3306 --databases permissions \
  --result-file="permissions-$stamp.sql"
# Accounts are not in a schema dump: record the gateway user's grants beside it.
mysql --defaults-extra-file=/secure/backup.cnf --host=perm-db.internal --port=3306 \
  --batch --skip-column-names -e "SHOW GRANTS FOR 'gateway'@'%'" > "permissions-$stamp.grants"
```

Replace `permissions` and `'gateway'@'%'` with the schema and account in your `PERMISSIONS_DB_DSN`. The dump holds grants and their audit history (`permissions_audit`): treat it like the state DB dump.

## Restore

1. Stop every gateway replica (or scale to 0).
2. **On a replacement cluster, recreate the roles first.** `pg_restore` creates no roles, and a table's grants to `gateway_app` fail to restore while that role does not exist. As an administrator: run the `gateway_owner` / `gateway_app` lines of `gateway-roles-….sql` with `psql`, set each password from your secret manager with psql's `\password gateway_owner` (it prompts; the password never appears in an argument or in history), and create the database with `OWNER gateway_owner`. A single-role deployment recreates its one role the same way.
3. Restore into the empty database as `gateway_owner`, credentials from the password file: `pg_restore --no-owner --host=state-db.internal --port=5432 --username=gateway_owner --dbname=gateway gateway-….dump`. With the roles in place, the dump's grants come back with the tables. With the split roles, re-run the [grants block](#state-db-roles) anyway, and check the result before starting a replica: `SELECT has_table_privilege('gateway_app', 'audit_calls', 'INSERT'), has_table_privilege('gateway_app', 'audit_calls', 'UPDATE')` answers `t`, `f`.
4. **Invalidate what the restore brought back.** A backup predates later logouts and `revoke-sessions` calls; restored, those sessions and refresh tokens are live again. Before starting the gateway:

   ```sql
   update sessions set revoked_at = now() where revoked_at is null;
   delete from oauth_refresh_tokens;
   ```

   Rotating `SESSION_SIGNING_KEY` at the same time also invalidates every outstanding session JWT. Everyone signs in again; that is the point.
5. **Re-check admin-API grants.** Grants revoked after the backup are back. Compare `permissions_audit` in the backup with your incident timeline, or with the live database if it survived, and revoke again.
6. **MySQL permissions store** (`permissions_store.driver: mysql`), if it was lost too:
   1. Restore the schema into an empty server: `mysql --defaults-extra-file=/secure/admin.cnf --host=perm-db.internal < permissions-….sql` (the dump carries its `CREATE DATABASE`).
   2. Recreate the gateway's account if the server is new, and re-apply every statement in `permissions-….grants`.
   3. Verify before booting: `SHOW GRANTS FOR 'gateway'@'%'` matches `permissions-….grants` line for line; logged in **as the gateway's account** (its own option file), `SELECT MAX(version) FROM permissions._sqlx_migrations` answers and is no newer than the image you are about to start knows; and `SELECT COUNT(*) FROM permissions.permissions_grants` is plausible against your records. A missing privilege otherwise surfaces only at boot (a refused migration) or at the first grant lookup; catch it here instead.
   4. Re-check its grants as in step 5: grants revoked after this backup are back.
7. Start the gateway with the image version that last ran on this schema or a newer one (see [Rollback](#rollback)). Boot re-applies nothing that is already recorded in `_sqlx_migrations` (state DB and MySQL store alike).

The audit rows written between the backup and the failure are gone; if you stream audit rows to a log pipeline (`logging.stream`), that copy is the only record of them.

## Upgrade

1. Read the release notes and, across a major version, the upgrade guide ([2.0](upgrading-to-2.md)). Config keys are never silently ignored: an unknown or renamed key aborts boot with a `line:column` pointer, so a bad config fails the first replica, not production traffic. Catch it before the rollout instead: run the new image's `db-mcp-gateway --config config.yml --check --no-secrets` in CI ([operator CLI](cli.md)) — every error at once, plus the connection budget to compare with each target's `max_connections`.
2. Back up the state DB, and the MySQL permissions store with its grants if you run one ([Backup](#backup)).
3. **Migrate.** Migrations are expand/contract, so old replicas keep working on the new schema while the rollout runs.
   - **One role** (`STATE_DB_URL` owns the schema): nothing to do here — the first new replica applies the migrations at boot.
   - **[Split roles](#state-db-roles)**: `gateway_app` cannot migrate, so migrate as `gateway_owner` before any new replica starts — a one-off job running the **new** image with `STATE_DB_URL` pointing at `gateway_owner`, stopped once `/readyz` answers (or `sqlx migrate run` from the release tag's checkout), then re-run the grants block as `gateway_owner`. A new replica started earlier exits at boot on the pending migration, and its restarts keep failing until the job has run; nothing is half-applied.
4. Bump the pinned image tag (`ghcr.io/developerz-ai/db-mcp-gateway:X.Y.Z`; avoid `:latest` and `:main` in production) and roll replicas one at a time.
5. Give each old replica a full drain: `terminationGracePeriodSeconds` ≥ 120 (80 s request drain + 20 s detached audit writes + pool close).
6. Watch `/readyz`, `tool_calls{outcome="audit_unavailable"}` and `config_reloads_total{result="error"}` after the rollout.

Login flows in progress during the rollout (a browser between `/authorize` and `/token`) can fail, because that state is per process; users simply retry.

## Rollback

Swap the image tag back to the previous release and roll again. From 2.0.3 onward a **one-release** rollback works in place: the older image boots on the newer schema, skips the migrations it does not know and logs `schema was migrated by a newer gateway release`. Revert any config key the newer release introduced first — the older image refuses unknown keys.

Going back more than one release, or to 2.0.2 and earlier, is not guaranteed in place: restore the pre-upgrade backup ([Restore](#restore)) or roll forward. Never delete rows from `_sqlx_migrations` to force an older image to boot. Details: [upgrading-to-2 §Rollback](upgrading-to-2.md#rollback).

## Rotating secrets

| Secret | How | Effect |
|---|---|---|
| Target DB password (`${FILE:…}`) | Update the file, change anything on that database entry (or the ref) and send `SIGHUP` | Fresh pool for that database; old connections drain |
| Target DB password (`${ENV:…}`) | Update the env and restart the replicas | — |
| `SESSION_SIGNING_KEY` | Update and restart all replicas together | Every session JWT is invalid; everyone signs in again |
| `OIDC_CLIENT_SECRET` | Add the new secret at the IdP, update, restart, remove the old one | None for users |
| Service token | [Spec 14](../initial-idea/14-service-tokens.md) runbook (`bin/mint-service-token`, config edit + rollout) | The old token stops working when the last replica rolls |
| TLS cert/key | Replace the files, send `SIGHUP` | New handshakes use the new cert |

`SIGHUP` goes in from outside the container — the image is distroless, with no `kill`: `docker kill --signal=HUP <container>`.
