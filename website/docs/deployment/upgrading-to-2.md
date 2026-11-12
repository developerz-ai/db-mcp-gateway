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
| Shutdown | immediate | drains in-flight requests (≤55 s) then detached audit work (≤20 s) | `terminationGracePeriodSeconds` ≥ 75 plus any preStop sleep. |
| Admin API | positional internals | unchanged HTTP surface; PATCH now merges constraints per key (absent keeps, `null` clears) | Clients that sent a full constraints object keep working; clients relying on "omitted key clears it" must send `null`. |
| `GET /mcp` (SSE) | greeting stream | `405` | Clients POST (Streamable HTTP). |

## New, opt-in

- **Hot reload:** `SIGHUP` re-reads the YAML atomically (all or nothing); admin mount/group, store driver and — while the admin API is mounted — the server set still need a restart.
- **Agent tiers:** `write_role`, `service_accounts[].max_concurrent_requests`, `require_upstream`, headers `x-dbmcp-run-id` / `x-dbmcp-on-behalf-of` ([headless agents](../usage/headless-agents.md)).
- **Tools:** `table_stats`, `db_activity`, `cancel_query`; `run_query` `dry_run`; `explain` `analyze` (reads only); `rows_affected` everywhere.
- **Target TLS:** `tls: verify_full` + `tls_ca_file` (Postgres `required` encrypts but does not verify).
- **Per-database pools:** `pool:` on server or database.

## Audit schema

Migrations `0010`–`0014` apply at boot (additive): `audit_call_intents`, history index, refresh-token session link, `mongo` db_type, upstream/rows_affected/sql_truncated columns. New outcomes: `abandoned`, `audit_unavailable`, `dry_run`, `cancelled`. Reporting queries that enumerated outcomes should add them.

## Rollback

Roll back the image; the 2.0 migrations are additive and 1.6 ignores the new columns/table. Revert config changes that only 2.0 understands (`write_role`, `pool:`, `gateway:`), or 1.6 will ignore them — it does not reject unknown keys.
