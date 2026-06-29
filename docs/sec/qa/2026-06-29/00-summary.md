# Security Deep-Dive — db-mcp-gateway

**Date:** 2026-06-29
**Scope:** Full source tree (`src/`, ~13.1k LOC) at `main` @ `9250579` (v0.1.0).
**Method:** Six parallel layer-focused audits (auth, authz, SQL exec + tools, credentials + audit, admin API, transport/DoS). Each finding was verified by reading the actual code; the headline `sql_guard` bypass was additionally re-verified by hand.

## Bottom line

The gateway is well-built. The hard invariants the project cares most about — credential confinement, group-based authz, synchronous in-transaction audit, parameterized SQL, fail-closed admin gating — hold. **No credential leak, no auth bypass, and no authz escalation was confirmed.**

The real exposure is concentrated in two places:

1. **`sql_guard` defense-in-depth is bypassable** — three High findings. A writable CTE, `SELECT … INTO`, or `EXPLAIN ANALYZE` of either reaches the target DB. This only causes harm if the target-DB `*_ro` role is over-privileged (i.e. the *second* line of defense has failed), which is exactly the case `sql_guard` exists to catch. All three are closed by one AST-tree walk.
2. **No rate limiting / resource caps anywhere** — the "one noisy user must not starve others" non-negotiable is unmet on every axis: no per-user concurrency limit, uncapped unauthenticated SSE connections, no statement-timeout floor, no outbound OIDC timeout, and client-disconnect does not actually `pg_cancel_backend`.

Plus two High auth **defaults/fail-open** issues that matter before the multi-replica Helm rollout: a committed default session-signing key used silently when unset, and `bearer_auth` passing through when `state.auth` is `None`.

## Findings by severity

| # | Severity | Title | File | Report |
|---|----------|-------|------|--------|
| S1 | **High** | Writable CTE (`WITH x AS (INSERT … RETURNING) SELECT …`) bypasses read-only guard | `src/exec/sql_guard.rs:83` | [01](01-sql-execution.md) |
| S2 | **High** | `SELECT … INTO new_table` bypasses read-only guard (creates table) | `src/exec/sql_guard.rs:83` | [01](01-sql-execution.md) |
| S3 | **High** | `EXPLAIN ANALYZE` executes; with S1 runs writes | `src/exec/sql_guard.rs:54` | [01](01-sql-execution.md) |
| A1 | **High** | Committed default session signing key used silently when `SESSION_SIGNING_KEY` unset | `src/auth/config.rs:12,107` | [02](02-authentication.md) |
| A2 | **High** | `bearer_auth` fails open (passes through) when `state.auth` is `None` | `src/transport/auth_middleware.rs:21` | [02](02-authentication.md) |
| S4 | Medium | No statement-timeout floor → unbounded query pins pool connection (DoS) | `src/exec/pg.rs:91` | [01](01-sql-execution.md) |
| S5 | Medium | Client disconnect does not `pg_cancel_backend`; query continues server-side | `src/exec/pg.rs:168` | [01](01-sql-execution.md) |
| S6 | Medium | Mongo rejector misses `$accumulator` (server-side JS) | `src/exec/mongo/rejector.rs:48` | [01](01-sql-execution.md) |
| T1 | Medium | No per-user / global rate or concurrency limit on request path | `src/transport/mod.rs:46` | [03](03-transport-dos.md) |
| T2 | Medium | Unauthenticated SSE endpoint, no connection cap (FD/task exhaustion) | `src/transport/sse.rs:16` | [03](03-transport-dos.md) |
| T3 | Medium | OIDC discovery/JWKS/token HTTP client has no timeout | `src/auth/oidc.rs:94` | [03](03-transport-dos.md) |
| A3 | Medium | Session revocation not honored across replicas; cache has no TTL | `src/auth/session.rs:189` | [02](02-authentication.md) |
| A4 | Med/Low | No TLS enforcement on OIDC issuer / discovered endpoints | `src/auth/oidc.rs:209` | [02](02-authentication.md) |
| C1 | Medium* | Boot DB-connect error may surface DSN+password via anyhow chain (*needs runtime check*) | `src/state/mod.rs:16`, `src/main.rs:31` | [04](04-credentials-audit.md) |
| C2 | Low | Secret plaintext never zeroized (no `zeroize`/`secrecy`) | `src/config/secret.rs:31` | [04](04-credentials-audit.md) |
| C3 | Low | `pruner::run_once` has no internal floor on `ttl_days` (0 ⇒ wipes audit) | `src/audit/pruner.rs:18` | [04](04-credentials-audit.md) |
| C4 | Low | serde_yaml parse error text + location echoed to boot log | `src/config/yaml.rs:79` | [04](04-credentials-audit.md) |
| ADM1 | Low | Read GETs upsert `permissions_users` outside audit tx | `src/transport/admin/middleware.rs:111` | [05](05-admin-api.md) |
| ADM2 | Low | Stale admin privilege from session-cached groups | `src/transport/admin/middleware.rs:92` | [05](05-admin-api.md) |
| S7 | Low | `pg_read_file` / `lo_export` pass the guard (function-blind) | `src/exec/sql_guard.rs` | [01](01-sql-execution.md) |
| AZ1 | Low | Empty-string `group` name accepted at boot | `src/config/yaml.rs:269` | [06](06-authorization.md) |
| A5 | Low | JWT alg taken from token header (RS/HS confusion shape; not exploitable in 9.3.1) | `src/auth/oidc.rs:166` | [02](02-authentication.md) |
| A6 | Low | `email` optional, `email_verified` never checked | `src/auth/oidc.rs:187` | [02](02-authentication.md) |

\* C1 severity is conditional on a runtime check (see report 04).

## Needs runtime verification (not yet confirmed)

- **C1** — feed a malformed `STATE_DB_URL`/`PERMISSIONS_DB_DSN` and inspect the stderr line `main` prints on exit. If the URL/password appears, C1 is a confirmed Medium credential leak.
- **S7 family** — depends on whether the deployed `*_ro` role can call `pg_read_file`/`lo_export` (it should not under least privilege).
- **Mongo `maxTimeMS`** vs cumulative `getMore` time (report 01, needs-verification §).

## Recommended fix order

1. **One `Query`-tree walk in `sql_guard`** closes S1, S2, S3 together. Highest priority — smallest change, removes all three High SQL findings. *(Security review required: SQL execution.)*
2. **Boot-time guards (A1, A2):** refuse to boot on the default signing key when not in mock mode; make the auth-less `AppState` a `#[cfg(test)]`-only constructor. *(Security review required: auth.)*
3. **Resource caps (S4, T1, T2, T3):** statement-timeout floor, per-user concurrency limit + load-shed, SSE connection semaphore, OIDC client timeouts.
4. **S5:** real `pg_cancel_backend` on future-drop; fix the inaccurate comment in `audit_dispatch.rs`.
5. **S6:** add `$accumulator` to the Mongo deny list (consider allow-list).
6. **C1 runtime check**, then C2–C4, A3–A6, ADM1–ADM2, AZ1 as hardening.

## Layers reviewed clean (no High/Medium)

- **Authorization** (`src/authz/`) — fail-closed, most-restrictive merge proven by proptests, wildcards match exactly, write actions correctly gated, cache invalidation race handled. Only Low/informational notes (report 06).
- **Credential redaction** broadly — hand-rolled `Debug` redaction on every secret-bearing type, `Deserialize`-only secrets, credential-free client view types, parameterized append-only audit. One conditional boot-path concern (C1).
