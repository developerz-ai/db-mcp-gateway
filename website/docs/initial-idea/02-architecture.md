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

```text
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

## Transport (wire protocol)

The gateway speaks **MCP over Streamable HTTP** (the 2025-03+ MCP transport), not the deprecated two-endpoint HTTP+SSE transport:

- A single configurable endpoint (default `/mcp`).
- `POST` carries client→server JSON-RPC 2.0 messages; the gateway replies with a JSON-RPC response (`application/json`), or `202 Accepted` for notifications.
- `GET` opens the server→client SSE stream for server-initiated messages. On connect it emits a non-normative `greeting` event (protocol version + server identity) so a plain `curl` confirms liveness, then holds open with keep-alives.

**Request `id` semantics.** The JSON-RPC `id` member is treated as a three-way distinction rather than a `null`/non-`null` flag, because JSON-RPC 2.0 and MCP disagree about what an explicit `"id": null` means and the gateway must not silently reinterpret one as the other:

| `id` on the wire | Meaning | Gateway response |
|---|---|---|
| **Absent** (member omitted) | JSON-RPC notification — no reply expected | `202 Accepted`, no body. `tools/call` never has a notification form, so a `tools/call` with no `id` is declined without executing a query. |
| **Null** (`"id": null` explicit) | MCP forbids null request ids (JSON-RPC 2.0 also `SHOULD NOT` be null). Not a notification. | `invalid_request` JSON-RPC error with `"id": null`. `tools/call` is rejected before any authz/query/audit work — the caller could never observe the outcome, so executing would just run an unowned query. |
| **Present** (string / number / other value) | A real request | Normal request/response, id echoed back on the reply. |

The distinction lives in `RequestId` (`Absent` / `Null` / `Present`) so the same rule can be enforced identically in stateless dispatch and in the `tools/call` fast path.

Protocol version: `2025-06-18`. The framing is hand-rolled JSON-RPC; it gets swapped for an official MCP server SDK when one stabilizes (see [11-roadmap](11-roadmap.md)). Transport owns framing only — auth, tool dispatch, and audit are separate layers below.

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

For organizations that need to survive a single gateway instance going down: run two replicas behind a load balancer. Session state is in the state DB, not in-process, so an **established** session (a Bearer JWT on `/mcp`) follows the request to whichever replica picks it up — sticky sessions are *not* required for the steady-state request path. The only singleton background task — audit retention pruning — uses an advisory lock in the state DB so only one replica runs it at a time.

**Session revocation is eventually consistent across replicas.** Each replica fronts the state DB with a small in-process session cache that has a freshness TTL (`SESSION_CACHE_TTL_SECONDS`, default 30s) and a hard size bound. A logout/revoke evicts the entry on the replica that handled it (immediate there), but other replicas keep serving their cached copy until it ages past the TTL and re-validates against `revoked_at`. The cross-replica revocation window is therefore ≤ the TTL — tune it down for faster propagation, up to spend fewer state-DB reads (see [04-auth-sso §Session tokens](04-auth-sso.md#session-tokens)).

**One exception: the MCP OAuth bridge's login leg.** The two stores that only have to outlive a single browser round-trip — pending IdP logins and one-time authorization codes — are in-process, not in the state DB (see [04-auth-sso](04-auth-sso.md)). A client that begins the login dance (`/authorize` → `/auth/callback` → `/token`) must reach the **same** replica for every step, or it sees `invalid_grant` from a replica that never saw the earlier step. Until that state also moves to the state DB (roadmap), an HA deployment must either run the bridge on a **single replica** or pin the login endpoints (`/authorize`, `/auth/callback`, `/token`) with **sticky routing**.

**Everything that is supposed to outlive the login is persisted.** Dynamic client registrations (`oauth_clients`, migration 0008) and refresh-token chains (`oauth_refresh_tokens`, migration 0009) both live in the state DB, so `/register` and `grant_type=refresh_token` are replica-agnostic and survive restarts and redeploys. That is what makes the configured "stay signed in" window (`REFRESH_TTL_DAYS`) real: with the chain in process memory, the effective ceiling was time-until-the-next-rollout, and every deploy signed every agent out. The bespoke `/auth/login` JSON flow has the same single-replica/sticky constraint for its login round-trip. None of this affects already-authenticated `/mcp` traffic.

## Statelessness

The gateway process is stateless apart from in-memory caches (JWKS, sessions, decoded permissions) and the MCP OAuth bridge's in-process login state (pending logins and one-time auth codes). Client registrations (`oauth_clients`) and refresh-token chains (`oauth_refresh_tokens`) live in the state DB, so both persist across restarts. Restarting the binary loses nothing that isn't reloadable from config + state DB — a login that is mid-round-trip is the one thing a restart drops, and the client simply retries it (its registration and its refresh chain both still resolve, so an already-signed-in agent notices nothing). Two replicas behind a load balancer is the path to HA; sticky sessions are not required for the steady-state `/mcp` request path because session state is in the state DB, but the OAuth bridge login dance needs single-replica or sticky routing (see [HA](#ha) above).

## What's deliberately not here

- **No query builder, no result UI.** Agents are the UX.
- **No write-mode default.** See [06-permissions](06-permissions.md) for opt-in writes.
- **No SaaS control plane.** Every install is self-hosted and self-contained.
- **No multi-tenant boundary.** One install per organization. Tenancy = run another install.

See: [03-mcp-tools](03-mcp-tools.md), [05-credentials](05-credentials.md), [07-logging-retention](07-logging-retention.md).
