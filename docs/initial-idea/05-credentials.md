# 05 — Credentials

## The promise

**No DB credential ever leaves the gateway.** Not in responses, not in logs, not in errors. The agent — and the developer — has no way to obtain a connection string from this system.

## What the gateway holds

For every `(server, database)` pair declared in config, the gateway needs:

- host, port, db name
- a Postgres (or MySQL/MSSQL) role
- the password / cert / IAM-token-issuer for that role

These come from one of three sources, resolved at config load:

1. **Inline literal** in `config.yaml` (dev only — rejected if `env=production`).
2. **Environment variable reference** — `${DB_PROD_RO_PASSWORD}` — resolved from the process env.
3. **Secret manager reference** — `vault:secret/prod/db/ro_password`, `aws-sm:arn:...`, `gcp-sm:projects/.../secrets/...`. Resolved at startup and on hot reload.

## Per-database role design

Every database gets its **own** Postgres role. Not one role per server. Not one role for everything.

| Aspect | Choice |
|---|---|
| Privilege | `SELECT` on intended schemas; nothing else by default |
| `statement_timeout` | Set on the role (`ALTER ROLE … SET statement_timeout`) — defense in depth on top of the gateway's own timeout |
| `idle_in_transaction_session_timeout` | Short — read-only debugging doesn't need long transactions |
| Row cap | Enforced gateway-side via `LIMIT` rewriting *and* by streaming the cursor and disconnecting at N |
| Naming | `mcp_gateway_<env>_<db>_ro` — boring, traceable in DB-side logs |

The repo will ship example SQL for provisioning these roles (see [09-deployment](09-deployment.md)).

## Why not IAM auth alone?

IAM auth (AWS RDS IAM, GCP Cloud SQL IAM) is supported as a credential *source* — the gateway swaps in a short-lived token instead of a password — but the *role concept stays*. IAM auth + a role with `SELECT` is the recommended setup on managed Postgres.

## Write access

Off by default. To enable:

1. The role granted to the gateway must have the write grants — gateway will not provision them for you.
2. Config must mark the `(server, database)` permission entry as `mode: read-write`.
3. The permission must be scoped to a specific group, with `require_reason: true` recommended.
4. Audit log captures the full SQL of every write.

This is intentionally several steps so it can't be enabled by accident.

## Connection pool

Per `(server, database)`:

- Max connections in config (default 5)
- Idle timeout (default 5 min)
- Acquire timeout (default 10s — fail fast so the agent gets a clear error)
- TLS required by default; reject non-TLS unless explicitly opted out for local dev

## Rotation

Credentials are re-read from their source on `SIGHUP` (config reload). Live connections aren't killed — new connections will use the new credential, old ones drain naturally. For forced rotation, restart the gateway; with two replicas, this is zero-downtime.

## What this rules out

- No "share my session credential with my coworker" — there's nothing to share.
- No connection-string export tool. Ever.
- No "let me see what credential you're using" admin endpoint. Logs show role name (not password) and only to operators.
