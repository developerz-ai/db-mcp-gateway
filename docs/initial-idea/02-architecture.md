# 02 — Architecture

## Components

| Component | Role |
|---|---|
| **Gateway binary** | Rust process. Speaks MCP to agents over HTTP/SSE. Holds DB credentials, enforces permissions, signs tokens, writes audit logs. |
| **Gateway state DB** | A small Postgres co-deployed with the gateway. Stores: SSO sessions, audit logs (hot window), per-user query stats. Not the customer's DB. |
| **Target databases** | The customer's actual databases (prod, staging, analytics…). Gateway connects with a per-database read-only role. |
| **Identity provider (SSO)** | Existing OIDC IdP (Okta, Google Workspace, Authentik, Keycloak…). Source of truth for users and group memberships. |
| **Config file** | YAML in git. Defines servers, databases, groups, permissions, retention, SSO settings. |

## Request path

```
┌─────────────┐    MCP/HTTP+SSE     ┌─────────────────────┐    pg wire    ┌──────────────┐
│ Agent       │ ──────────────────▶ │  Gateway (Rust)     │ ────────────▶ │ Target DB    │
│ (Claude     │   Bearer: <sso-jwt> │                     │  role=ro_user │ (read-only   │
│  Code, …)   │ ◀────────────────── │  ┌───────────────┐  │ ◀──────────── │  role)       │
└─────────────┘   tool result JSON  │  │ authz + audit │  │  result rows  └──────────────┘
                                    │  └───────────────┘  │
                                    │         │            │
                                    │         ▼            │
                                    │   ┌──────────┐       │
                                    │   │ state DB │       │
                                    │   │ (audit)  │       │
                                    │   └──────────┘       │
                                    └─────────────────────┘
```

## Layers inside the gateway

One reason to change per layer. Don't blur these.

| Layer | Owns | Why it's its own thing |
|---|---|---|
| **Transport** | MCP over HTTP+SSE, JSON-RPC framing, capability negotiation | Protocol churns; isolate it |
| **Auth** | OIDC flow, JWT verification, session cache, group resolution | Security boundary; must be auditable in isolation |
| **Authz** | Map (user, groups) × (server, database, action) → allow/deny + constraints | Pure function over config; testable without a DB |
| **Tool dispatch** | The MCP tool surface: `list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain` | Stable contract to agents |
| **Query exec** | Connection pool per DB, statement timeout, row cap, cancellation | Where most of the safety lives |
| **Audit** | Append-only writes to state DB, structured logs, retention pruner | Append-only, never read by hot path |
| **Config** | Load + validate YAML, hot reload on SIGHUP, secrets resolution | Decoupled so config errors fail at boot, not at query time |

## Process model

- Single binary, single process, async runtime (tokio).
- Connection pool per *target database*, sized in config.
- One Postgres pool for the state DB.
- A background task per pool for health checks; one for audit retention pruning; one for SSO key rotation.

## Concurrency

The gateway is the shared substrate for an *entire engineering org* hammering away from multiple agents at once. Every layer is built for that load shape from the start.

- **All I/O is async.** Tokio runtime, axum HTTP, sqlx async driver. One slow query never blocks another developer's request.
- **No per-user serialization.** A developer can run multiple agents (Claude Code in one repo, Cursor in another) under the same SSO identity, and they share the session token but not the connection — every request gets a fresh pooled connection.
- **Per-database concurrency cap.** The pool `max_connections` is the upper bound. Bursts beyond that queue at the gateway with the `acquire_timeout` ceiling — agents see a clean `unavailable` error instead of cascading timeouts down to the DB.
- **Tool dispatch is non-blocking.** Each MCP request is its own tokio task. Cancellations (agent disconnect, statement timeout) propagate cleanly down to the DB driver — `pg_cancel_backend` on Postgres — so an abandoned query doesn't burn a connection until it finishes on its own.
- **Audit writes don't queue head-of-line.** The audit log writer has its own state-DB pool, separate from session reads, so a burst of queries doesn't starve session validation or vice versa.
- **Fairness.** When a `(server, database)` pool is saturated, waiters are FIFO. We will not implement per-user priority in v1; if one user is dominating prod, the operator's lever is the permissions config (lower `row_limit`, lower `statement_timeout_ms`), not in-gateway scheduling.

### What this means in practice

| Scenario | Behavior |
|---|---|
| 50 agents call `list_databases` simultaneously | All return in parallel; no target DB hit at all — served from cached metadata |
| 10 agents `run_query` against `prod/app` (pool max 5) | First 5 execute; next 5 queue up to `acquire_timeout`; queue beyond that returns `unavailable` |
| One agent runs a slow 25s query | Other agents' queries against the same DB execute in parallel on other pool connections; that agent's own *next* query waits or fails fast |
| Agent disconnects mid-query | `pg_cancel_backend` fires, the connection returns to the pool within seconds, audit log records `outcome: cancelled` |
| 1000 audit writes in 10s | Audit pool absorbs the burst; if it can't, the *request* fails (synchronous audit invariant — see [01-overview](01-overview.md)) rather than queueing audit and lying about durability |

### HA

For organizations that need to survive a single gateway instance going down: run two replicas behind a load balancer. Session state is in the state DB, not in-process, so sessions follow the request to whichever replica picks it up. Sticky sessions are *not* required. The only singleton background task — audit retention pruning — uses an advisory lock in the state DB so only one replica runs it at a time.

## Statelessness

The gateway process is stateless apart from in-memory caches (JWKS, sessions, decoded permissions). Restarting the binary loses nothing that isn't reloadable from config + state DB. Two replicas behind a load balancer is the path to HA; sticky sessions are not required because session state is in the state DB.

## What's deliberately not here

- **No query builder, no result UI.** Agents are the UX.
- **No write-mode default.** See [06-permissions](06-permissions.md) for opt-in writes.
- **No SaaS control plane.** Every install is self-hosted and self-contained.
- **No multi-tenant boundary.** One install per organization. Tenancy = run another install.

See: [03-mcp-tools](03-mcp-tools.md), [05-credentials](05-credentials.md), [07-logging-retention](07-logging-retention.md).
