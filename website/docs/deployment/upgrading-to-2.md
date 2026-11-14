# Upgrading to 2.0

2.0 is the hardening + agent-power release (plan 101). Every break below fails
**at boot** with the variable or key named — a misconfigured 2.0 never serves
traffic half-configured. Check each item before you roll.

## Must change

| What | 1.x | 2.0 | Action |
|---|---|---|---|
| Metrics endpoint | `/metrics` on the public listener | served only on `METRICS_BIND` (default `127.0.0.1:9090`) | Set `METRICS_BIND=0.0.0.0:9090`, expose container/service port `9090`, point the ServiceMonitor (or scraper) at it. Keep it off the public ingress. |
| Mock signing key | `OIDC_MOCK_MODE=true` | `ALLOW_INSECURE_SIGNING_KEY=true`, accepted only with a loopback `OIDC_ISSUER` | Rename; production never sets it. |
| OIDC env | issuer / client id could be absent | `OIDC_ISSUER` and `OIDC_CLIENT_ID` required | Set both. |
| Write grants | `query_write` ran on the database's single `role` | `query_write` requires `write_role` + `write_password` on the database (wildcards expanded); reads always run as `role` in a read-only transaction | Provision a read-only `role` and a separate write role ([config reference](config-reference.md)), move the write-capable role to `write_role`. The gateway never provisions roles. |
| Unknown YAML keys | ignored | boot fails | Remove stray keys. |
| Zero / out-of-range values | accepted | boot fails: `row_limit: 0`, `statement_timeout_ms: 0`, `port: 0`, `STATE_DB_POOL_SIZE=0`, `MAX_CONCURRENT_*=0`, `PERMISSIONS_CACHE_TTL_SECONDS` > 300, `REFRESH_TTL_DAYS` outside 1–366, `SESSION_TTL_HOURS` outside 1–168, pool `min_connections` > `max_connections` | Fix the value. |
| Inline secrets | allowed everywhere | rejected when `gateway.env: production` | Use `${ENV:…}` / `${FILE:…}`. |
| Shutdown | immediate | drains in-flight requests for 80 s (the 75 s `/mcp` request timeout + 5 s), then detached audit work (≤20 s), then closes the two state-DB pools (≤10 s each) | `terminationGracePeriodSeconds` ≥ 120 plus any preStop sleep. A shorter grace period `SIGKILL`s a pod mid-drain and loses the completion audit rows of slow calls. |
| Admin API | positional internals | unchanged HTTP surface; PATCH now merges constraints per key (absent keeps, `null` clears) | Clients that sent a full constraints object keep working; clients relying on "omitted key clears it" must send `null`. |
| `GET /mcp` (SSE) | greeting stream | `405` | Clients POST (Streamable HTTP). |

## New, opt-in

- **Hot reload:** `SIGHUP` re-reads the YAML atomically (all or nothing); admin mount/group, store driver and — while the admin API is mounted — the server set still need a restart.
- **Agent tiers:** `write_role`, `service_accounts[].max_concurrent_requests`, `require_upstream`, headers `x-dbmcp-run-id` / `x-dbmcp-on-behalf-of` ([headless agents](../usage/headless-agents.md)).
- **Tools:** `table_stats`, `db_activity`, `cancel_query`; `run_query` `dry_run`; `explain` `analyze` (reads only); `rows_affected` everywhere.
- **Target TLS:** `tls: verify_full` + `tls_ca_file` (Postgres `required` encrypts but does not verify).
- **Per-database pools:** `pool:` on server or database.

## State DB schema

Migrations apply at boot.

| Migration | Change | Who it affects |
|---|---|---|
| `0010`–`0014` | Additive: `audit_call_intents`, history index, refresh-token session link, `mongo` db_type, upstream/rows_affected/sql_truncated columns | Nobody — new objects only |
| `0015` | Drops `audit_calls_user_sub_idx` and `audit_calls_db_type_idx` | Ad-hoc reporting queries that filtered `audit_calls` by `user_sub` alone or by `db_type` lose their dedicated index. `(user_sub, occurred_at)` and the history index still serve per-user lookups. |
| `0016` | Drops `sessions.agent_client` | **Breaking for reports** that select `sessions.agent_client` — the query fails. The column was always NULL; read the per-call client banner from `audit_calls.agent_client` instead. |
| `0017` (2.1.0) | Adds `oauth_refresh_tokens.chain_id` and the `oauth_refresh_rotated` tombstone table | None. Refresh-token reuse outside a 10 s grace now revokes the whole chain. `chain_id` keeps a default, so 2.0.3 still inserts after a rollback. |
| `0018` (2.1.0) | Adds `sql`, `sql_truncated` and `reason` to `audit_call_intents` | None. An `abandoned` row the reaper writes now says what ran. |
| `0019` (2.2.0) | Adds nullable `oauth_clients.client_name` | None. The consent page shows the self-registered name, marked unverified. 2.1.0 still inserts and reads. |
| `0020` (2.2.1) | Partial indexes on soft-deleted `permissions_*` rows | None — supports the pruner, which now hard-deletes soft-deleted users/databases/grants and `permissions_audit` rows older than `AUDIT_RETENTION_DAYS` |

New outcomes: `abandoned`, `audit_unavailable`, `dry_run`, `cancelled`. Reporting queries that enumerated outcomes should add them.

## MySQL permissions store

Only for `permissions_store.driver: mysql`. Its migrations `0004` (identity and routing columns move to `utf8mb4_0900_as_cs`, so SSO subjects and server names compare case-sensitively) and `0005` (the `db_type` CHECK constraint is rebuilt to admit `mongo`) need **MySQL 8.0**. MariaDB has no `utf8mb4_0900_as_cs` collation, so `0004` fails there and the gateway refuses to boot. CI and the dev stack run `mysql:8`.

## Rollback

**From 2.0.3, rolling back one release works in place.** The gateway boots on a state DB (or MySQL permissions store) that a newer release has migrated. It skips the migration versions it does not know and logs `schema was migrated by a newer gateway release` at boot. Migrations follow expand/contract: a drop lands only in a release *after* the one that stopped using the object. So release N-1 always runs on schema N. Going back further is not guaranteed, because the older code may need something a later migration dropped. If you need to go back further, roll forward instead, or restore the state DB from a backup.

A migration that already ran and whose file was later edited still refuses boot, on every version. The gateway never re-runs or skips a changed migration.

**Up to and including 2.0.2 (and every 1.x), rollback across a migration is not possible in place.** Those images refuse to boot on a schema that carries a migration they don't know: `migration N was previously applied but is missing in the resolved migrations`. Deleting rows from `_sqlx_migrations` to force the older image to boot is not a fix. The next upgrade would re-run migrations that are not idempotent, and it fails on objects that already exist. To get back to one of those images, restore the state DB from a backup taken before the upgrade. For 2.0 → 1.6 that means migrations `0010` onward. Otherwise, roll forward.

In every case, revert any config the newer release introduced (`write_role`, `pool:`, `gateway:`). 2.0 refuses unknown YAML keys at boot, and 1.x silently ignores them.
