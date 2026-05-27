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

## Statelessness

The gateway process is stateless apart from in-memory caches (JWKS, sessions, decoded permissions). Restarting the binary loses nothing that isn't reloadable from config + state DB. Two replicas behind a load balancer is the path to HA; sticky sessions are not required because session state is in the state DB.

## What's deliberately not here

- **No query builder, no result UI.** Agents are the UX.
- **No write-mode default.** See [06-permissions](06-permissions.md) for opt-in writes.
- **No SaaS control plane.** Every install is self-hosted and self-contained.
- **No multi-tenant boundary.** One install per organization. Tenancy = run another install.

See: [03-mcp-tools](03-mcp-tools.md), [05-credentials](05-credentials.md), [07-logging-retention](07-logging-retention.md).
