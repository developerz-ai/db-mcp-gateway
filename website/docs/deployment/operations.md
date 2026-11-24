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

## Backup

Back up the state DB like any production Postgres: continuous archiving / PITR if you have it, otherwise a scheduled `pg_dump`:

```bash
pg_dump --format=custom --no-owner \
  --dbname="$STATE_DB_URL" --file="gateway-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

- **Retention matches the audit policy.** The gateway prunes rows past `AUDIT_RETENTION_DAYS` (default 90) hourly, but your backups keep whatever they contain for as long as you keep the backups. Set backup retention to the same window, or deliberately longer if compliance wants it ([spec 07](../initial-idea/07-logging-retention.md#retention-surfaces-outside-the-gateway)).
- **Treat dumps as sensitive.** They hold SQL text, reasons and emails, plus session and refresh-token rows. They never hold target DB credentials.
- MySQL permissions store: `mysqldump --single-transaction` on its schema, on the same schedule.
- Take one right before every upgrade.

## Restore

1. Stop every gateway replica (or scale to 0).
2. Restore into an empty database: `pg_restore --no-owner --dbname="$STATE_DB_URL" gateway-….dump`.
3. **Invalidate what the restore brought back.** A backup predates later logouts and `revoke-sessions` calls; restored, those sessions and refresh tokens are live again. Before starting the gateway:

   ```sql
   update sessions set revoked_at = now() where revoked_at is null;
   delete from oauth_refresh_tokens;
   ```

   Rotating `SESSION_SIGNING_KEY` at the same time also invalidates every outstanding session JWT. Everyone signs in again; that is the point.
4. **Re-check admin-API grants.** Grants revoked after the backup are back. Compare `permissions_audit` in the backup with your incident timeline, or with the live database if it survived, and revoke again.
5. Start the gateway with the image version that last ran on this schema or a newer one (see [Rollback](#rollback)). Boot re-applies nothing that is already recorded in `_sqlx_migrations`.

The audit rows written between the backup and the failure are gone; if you stream audit rows to a log pipeline (`logging.stream`), that copy is the only record of them.

## Upgrade

1. Read the release notes and, across a major version, the upgrade guide ([2.0](upgrading-to-2.md)). Config keys are never silently ignored: an unknown or renamed key aborts boot with a `line:column` pointer, so a bad config fails the first replica, not production traffic.
2. Back up the state DB.
3. Bump the pinned image tag (`ghcr.io/developerz-ai/db-mcp-gateway:X.Y.Z`; avoid `:latest` and `:main` in production) and roll replicas one at a time. The first new replica applies the migrations at boot; migrations are expand/contract, so old replicas keep working on the new schema while the rollout runs.
4. Give each old replica a full drain: `terminationGracePeriodSeconds` ≥ 120 (80 s request drain + 20 s detached audit writes + pool close).
5. Watch `/readyz`, `tool_calls{outcome="audit_unavailable"}` and `config_reloads_total{result="error"}` after the rollout.

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
