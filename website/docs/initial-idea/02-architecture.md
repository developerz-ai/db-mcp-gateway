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
- `GET` returns `405 Method Not Allowed` (`Allow: POST`), before authentication. The gateway never initiates server→client messages, so it offers no SSE stream; MCP 2025-06-18 lets a server answer `GET` with `405` instead. (An idle stream also pinned a socket per unauthenticated caller.)
- One JSON-RPC message per `POST`. A batch array is refused with `invalid_request` (`-32600`, message `batch requests are not supported`) — MCP 2025-06-18 removed batching.
- `POST` must carry `Content-Type: application/json` (case-insensitive; parameters such as `charset` allowed). Anything else, or no `Content-Type` at all, is `415 Unsupported Media Type` with a `-32600` body and `"id": null`. Every MCP SDK client transport sends it, and the reference SDK server enforces the same rule.
- `MCP-Protocol-Version`: the gateway only negotiates `2025-06-18` (`initialize` always answers it). After `initialize`, a request that carries the header must name exactly that version, once. Any other value, or a repeated header, is `400 Bad Request` with a `-32600` body echoing the request `id` (MCP 2025-06-18 §Protocol Version Header). An **absent** header is accepted: the spec has the server assume its backwards-compatible default rather than refuse. `initialize` itself is exempt, because it is the request that negotiates the version.

**Framing errors.** The body is parsed to JSON first, then to a request, so every failure has a JSON-RPC shape (HTTP 200 unless noted):

| Body | Response |
|---|---|
| Not JSON | `-32700` `Parse error`, `"id": null` |
| JSON array (batch) | `-32600` `batch requests are not supported`, `"id": null` |
| JSON, but not a request object (`42`, `{}`, missing `method`, `jsonrpc` ≠ `"2.0"`) | `-32600` `Invalid request`, echoing `id` when it can be read from the object, else `null` |
| Unreadable or over the size limit (1 MiB) | the HTTP status of the failure (e.g. `413`) with a `-32600` body |
| Readable, but `Content-Type` is not `application/json` | `415` with a `-32600` body (checked after the body is read, so an oversized body is still `413`) |

**Request `id` semantics.** The JSON-RPC `id` member is treated as a three-way distinction rather than a `null`/non-`null` flag, because JSON-RPC 2.0 and MCP disagree about what an explicit `"id": null` means and the gateway must not silently reinterpret one as the other:

| `id` on the wire | Meaning | Gateway response |
|---|---|---|
| **Absent** (member omitted) | JSON-RPC notification — no reply expected | `202 Accepted`, no body. `tools/call` never has a notification form, so a `tools/call` with no `id` is declined without executing a query. |
| **Null** (`"id": null` explicit) | MCP forbids null request ids (JSON-RPC 2.0 also `SHOULD NOT` be null). Not a notification. | `invalid_request` JSON-RPC error with `"id": null`. `tools/call` is rejected before any authz/query/audit work — the caller could never observe the outcome, so executing would just run an unowned query. |
| **Present, string or integer number** | A real request with a well-typed MCP `RequestId` | Normal request/response, id echoed back on the reply. |
| **Present, unsupported type** (boolean, array, object, fractional number) | MCP defines `RequestId` as `string \| number`; JSON-RPC 2.0 also says numbers `SHOULD NOT` be fractional. Neither a valid request id nor a notification. | `invalid_request` JSON-RPC error with the sender's id echoed verbatim. `tools/call` is rejected before any authz/query/audit work — same reasoning as the null case. |

The distinction lives in `RequestId` (`Absent` / `Null` / `Present`, with `Present` validated by `is_invalid_type`) and is applied once, in `transport/mcp_handler.rs`, before the request is routed to stateless dispatch or to `tools/call`.

**Request ids.** The JSON-RPC `id` above is the client's correlation value and is only ever echoed in the envelope. Separately, the outermost middleware mints a gateway UUID per HTTP request and returns it as the `x-request-id` header on every response — success, `401`, `404`, `405`, `429`, `503`. Error bodies, the `tool_dispatch` span, `audit_calls.request_id` and admin errors all use that same value. A client-supplied `x-request-id` (≤128 chars of `[A-Za-z0-9._:-]`) is logged as `client_request_id` for correlation only — never the audit key.

Protocol version: `2025-06-18`. The protocol vocabulary (JSON-RPC envelope, MCP payload types, tool names) lives in `src/mcp/`, which both the transport and the tools import. The framing is hand-rolled JSON-RPC; it gets swapped for an official MCP server SDK when one stabilizes (see [11-roadmap](11-roadmap.md)). Transport owns framing only — auth, tool dispatch, and audit are separate layers below.

## Layers inside the gateway

One reason to change per layer. Don't blur these.

| Layer | Owns | Why it's its own thing |
|---|---|---|
| **Transport** | MCP over Streamable HTTP, JSON-RPC framing, capability negotiation | Protocol churns; isolate it |
| **Auth** | OIDC flow, JWT verification, session cache, group resolution | Security boundary; must be auditable in isolation |
| **Authz** | Map (user, groups) × (server, database, action) → allow/deny + constraints | Pure function over config; testable without a DB |
| **Tool dispatch** | The MCP tool surface: `list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain` | Stable contract to agents |
| **Query exec** | Connection pool per DB, statement timeout, row cap, cancellation | Where most of the safety lives |
| **Audit** | Two-phase append-only writes to state DB (intent before the target call, completion after), reaper, shutdown drain, stream sinks, retention pruner | Append-only, never read by hot path |
| **Config** | Load + validate YAML, hot reload on SIGHUP, secrets resolution | Decoupled so config errors fail at boot, not at query time |

## Process model

- Single binary, single process, async runtime (tokio).
- Connection pool per *target database*, sized in config (default 4 connections, sized from the 2026-11-12 baseline; min 0, idle connections closed after 5 min — an idle gateway holds no target connection). Opened on first use; replaced when the target rejects its credentials (password rotation) or on config reload; a failed open is remembered for 5 s so a dead target answers `unavailable` at once.
- Two state-DB pools and the listener's own connections: the request pool (`STATE_DB_POOL_SIZE`: sessions, authz reads, audit writes), a fixed background pool of 2 (pruner, reaper, auth GC), and 2 unpooled connections for the permissions `LISTEN` and its liveness ping (a silently dead connection would keep a pool slot until TCP gives up on it; unpooled, it costs only its socket) — the listener holds its connection for the life of the process, so on the request pool it would starve requests (with `STATE_DB_POOL_SIZE=1`, every one).
- Boot retries the state DB with backoff for `STATE_DB_CONNECT_TIMEOUT_SECONDS` (default 60) before exiting; the HTTP listener binds only after the state DB is up and migrated.
- No target-DB health checks: `/readyz` never depends on a target database, so one dead target cannot take the gateway out of rotation. One background task for audit retention pruning; one for the audit intent reaper; one for SSO key rotation.
- Detached work that must outlive a request but not the process (the audit drop guard's retry, stream-sink deliveries, target-side cancels) runs on one tracked task set that `main` drains, bounded, at shutdown.

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
| 10 agents `run_query` against `prod/app` (pool max 4) | First 4 execute; next 6 queue up to `acquire_timeout`; queue beyond that returns `unavailable` |
| One agent runs a slow 25s query | Other agents' queries against the same DB execute in parallel on other pool connections; that agent's own *next* query waits or fails fast |
| Agent disconnects mid-query | `pg_cancel_backend` fires, the connection returns to the pool within seconds, audit log records `outcome: cancelled` |
| 1000 audit writes in 10s | Audit pool absorbs the burst; if it can't, the *request* fails with `audit_unavailable` (synchronous audit invariant — see [01-overview](01-overview.md)) rather than queueing audit and lying about durability |
| Gateway killed between the target commit and the audit row | The intent row committed before the target call survives; the reaper records the call as `outcome: abandoned` ([07](07-logging-retention.md) §"Intent and completion") |

### HA

For organizations that need to survive a single gateway instance going down: run two replicas behind a load balancer. Session state is in the state DB, not in-process, so an **established** session (a Bearer JWT on `/mcp`) follows the request to whichever replica picks it up — sticky sessions are *not* required for the steady-state request path. Audit retention pruning and the audit intent reaper run on every replica, each under its own transaction-scoped advisory lock in the state DB, so only one replica deletes a batch or sweeps at a time.

**Session revocation is eventually consistent across replicas.** Each replica fronts the state DB with a small in-process session cache that has a freshness TTL (`SESSION_CACHE_TTL_SECONDS`, default 30s) and a hard size bound. A logout/revoke evicts the entry on the replica that handled it (immediate there), but other replicas keep serving their cached copy until it ages past the TTL and re-validates against `revoked_at`. The cross-replica revocation window is therefore ≤ the TTL — tune it down for faster propagation, up to spend fewer state-DB reads (see [04-auth-sso §Session tokens](04-auth-sso.md#session-tokens)).

**The login dance needs no sticky routing either.** Every piece of OAuth state lives in the state DB: pending IdP logins, consents awaiting a decision and one-time authorization codes (`oauth_pending_flows`, `oauth_pending_consents`, `oauth_auth_codes`, migration 0022), dynamic client registrations (`oauth_clients`, migration 0008) and refresh-token chains (`oauth_refresh_tokens`, migration 0009). So each step of a login — `/register`, `/authorize`, the IdP's redirect to `/auth/callback`, the consent `POST /authorize/consent`, `/token` — may land on any replica, as may the bespoke `/auth/login` → `/auth/callback` JSON flow. Every take of a pending login, consent or code is a single `DELETE … RETURNING`, so two replicas racing to redeem one code mint one grant: the other gets `invalid_grant`. Replicas must share `SESSION_SIGNING_KEY` — they already must for each other's bearers to verify — because the gateway's IdP-side PKCE verifier and ID-token nonce are derived from the login's `state` under a key derived from it, not stored (see [04-auth-sso §State & persistence](04-auth-sso.md#state--persistence)). This holds once every replica runs a release with migration 0022: during a rolling upgrade from 2.3.x, an old replica keeps its login state in memory, so a login that crosses versions fails cleanly (a 400 page, or `invalid_grant` at `/token`) and is retried — see [09-deployment §Upgrades](09-deployment.md#upgrades). Persisting the refresh chain is also what makes the configured "stay signed in" window (`REFRESH_TTL_DAYS`) real: with the chain in process memory, the effective ceiling was time-until-the-next-rollout, and every deploy signed every agent out.

## Statelessness

The gateway process is stateless apart from in-memory caches (JWKS, sessions, decoded permissions). Login state (pending logins, consents, authorization codes), client registrations and refresh-token chains live in the state DB, so all of it persists across restarts. Restarting the binary loses nothing that isn't reloadable from config + state DB — not even a login that is mid-round-trip, as long as its next step's state is unconsumed and unexpired: its callback, consent or `/token` step completes on another replica or on the restarted one. A replica stopped in the middle of a step it had already taken (a code redemption after the take, before the answer) leaves nothing to retry; the client restarts authorization. Two replicas behind a load balancer is the path to HA, with no sticky sessions for any route (see [HA](#ha) above).

## What's deliberately not here

- **No query builder, no result UI.** Agents are the UX.
- **No write-mode default.** See [06-permissions](06-permissions.md) for opt-in writes.
- **No SaaS control plane.** Every install is self-hosted and self-contained.
- **No multi-tenant boundary.** One install per organization. Tenancy = run another install.

See: [03-mcp-tools](03-mcp-tools.md), [05-credentials](05-credentials.md), [07-logging-retention](07-logging-retention.md).
