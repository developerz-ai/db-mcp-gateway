# 05 — Credentials

## The promise

**No DB credential ever leaves the gateway.** Not in responses, not in logs, not in errors. The agent — and the developer — has no way to obtain a connection string from this system.

## What the gateway holds

For every `(server, database)` pair declared in config, the gateway needs:

- host, port, db name
- a Postgres (or MySQL/MSSQL) role
- the password / cert / IAM-token-issuer for that role

These come from one of four sources, resolved at config load. Unresolved references abort boot — the gateway never serves a request it can't authenticate to.

1. **Inline literal** in `config.yaml` (dev only — `gateway.env: production` rejects it at boot, naming the field, never the value; applies to service-account tokens too).
2. **Environment variable reference** — `${ENV:DB_PROD_RO_PASSWORD}` — resolved from the process env at startup.
3. **File reference** — `${FILE:/run/secrets/db-prod-ro-password}` — read from disk at startup. Pairs with k8s sealed-secrets / external-secrets-operator / Vault Agent sidecar (all of which materialise secrets as files). Re-read on pool open so file rotation works without a restart.
4. **Secret manager reference** — `vault:secret/prod/db/ro_password`, `aws-sm:arn:...`, `gcp-sm:projects/.../secrets/...`. Recognised today; backend integrations land later. Until then, the gateway refuses to start rather than failing on first DB connect.

## Per-database role design

Every database gets its **own** Postgres role. Not one role per server. Not one role for everything.

| Aspect | Choice |
|---|---|
| Privilege | `SELECT` on intended schemas; nothing else by default |
| `statement_timeout` | Set on the role (`ALTER ROLE … SET statement_timeout`) — defense in depth on top of the gateway's own timeout |
| `idle_in_transaction_session_timeout` | Short — read-only debugging doesn't need long transactions |
| Row cap | Enforced gateway-side by streaming the cursor, breaking at N, and cancelling the backend so it stops generating rows nobody asked for (see below) |
| Naming | `mcp_gateway_<env>_<db>_ro` — boring, traceable in DB-side logs |

The repo will ship example SQL for provisioning these roles (see [09-deployment](09-deployment.md)).

### Row cap: cancel on truncate

`row_limit` must bound **server-side** work, not just the client-visible row count. sqlx always issues the extended-protocol portal `Execute` with `limit: 0` (no server-side row cap — deliberate, to avoid parallel-worker pessimization), so breaking the Rust-side read loop at N does NOT stop Postgres from generating and queueing the rest of the result. The pooled connection cannot accept the next command (`COMMIT` included) until that queued traffic is fully read — `wait_until_ready` drains it silently on the next `.await`. That defeats the row cap on exactly the queries where it matters.

Contract:

- Applies to **reads**. A truncated write is drained and committed instead — rolling it back would report rows as written that were not (see [03-mcp-tools](03-mcp-tools.md) §`run_query`). The byte cap (32 MiB of decoded values) truncates the same way as the row cap.
- On truncation, the exec layer fires an identity-checked `pg_cancel_backend` through the dedicated **cancel pool** — same mechanism used for a client disconnect, invoked inline. The backend then aborts server-side rather than continuing to produce rows nobody asked for.
- The now-aborted transaction only accepts `ROLLBACK`, so the exec layer follows the cancel with `tx.rollback()` instead of `tx.commit()`.
- **Cleanup failures do not fail the request.** The truncated rows already collected are the result. `pg_cancel_backend` returning `false` means the backend is already gone (equivalent to success) and is not logged. Cancellation execution errors and `rollback` errors are logged at `warn` level for observability, never surfaced to the client — a valid truncated read must not be turned into a failure by cleanup noise.
- The non-truncated path is unchanged: plain `tx.commit()`, errors propagated as typed `ExecError`s.
- **A cancel only hits the query it was meant for.** A PID is reused across pooled callers, so a late cancel could land on the next caller's statement. Each transaction sets `SET LOCAL application_name = 'dbmcp-<uuid>'`, and the cancel is `SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE pid = $1 AND application_name = $2` — it fires only while that transaction is still running.

### No session state survives a pooled connection

Every connection returned to the pool runs `RESET ALL; SELECT pg_advisory_unlock_all()` before the next caller gets it; a connection whose reset fails is closed, not reused. Ad-hoc SQL runs as an unnamed statement, so it does not accumulate in the connection's prepared-statement cache. `DISCARD ALL` is not used: it would drop prepared statements the driver's cache still believes exist.

Cancellation safety (CLAUDE.md §Cancellation safety) still holds: if the request future is dropped mid-query (agent disconnect / outer `tokio::time::timeout`), the `CancelOnDrop` guard fires `pg_cancel_backend` from a detached task. Disarming happens only after the inline cleanup returns, so a hang during rollback still hands the cancel off to the guard on outer-timeout kick-in.

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

- Max connections in config (default 4, sized from the 2026-11-12 production baseline: per-database concurrency 0–1)
- Min connections 0 and idle timeout 5 min: the pool opens on first use and an idle gateway holds no target connection
- Acquire timeout 5 s — fail fast so the agent gets `unavailable`. It is spent before the statement timeout starts, never counted against it
- A separate cancel pool (2 connections, lazy) carries `pg_cancel_backend`, so cancels never queue behind the queries they are cancelling
- Mongo: the same sizing, plus a 5 s server-selection and connect timeout
- TLS required by default; reject non-TLS unless explicitly opted out for local dev

## Rotation

A rotated password needs no restart. When the target rejects the credentials (SQLSTATE class `28` on Postgres, an authentication error on Mongo), the adapter for that `(server, database)` is marked stale and the registry replaces it on the next call, resolving the password reference again — so a rewritten `${FILE:…}` mount takes effect on its own. The call that hit the rejection fails `unavailable`; the next one uses the new password.

Credentials are re-read from their source on `SIGHUP` (config reload). Live connections aren't killed — new connections will use the new credential, old ones drain naturally. For forced rotation, restart the gateway; with two replicas, this is zero-downtime.

## What this rules out

- No "share my session credential with my coworker" — there's nothing to share.
- No connection-string export tool. Ever.
- No "let me see what credential you're using" admin endpoint. Logs show role name (not password) and only to operators.
- No DSN in a boot failure. A driver connect error can quote the URL it was handed (and thus the password); the gateway logs the error *type* only and exits with a credential-free message. Same discipline as the admin handlers.
