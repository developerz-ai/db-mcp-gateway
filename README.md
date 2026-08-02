<p align="center">
  <img src="website/static/img/logo.png" alt="db-mcp-gateway" width="200">
</p>

<h1 align="center">db-mcp-gateway</h1>

**Self-hosted MCP gateway for AI agents that need database access — without ever handing out a database URL.** 🔐

Your team deploys it once. Developers add one URL to their AI agent's MCP config. The gateway holds every credential, enforces SSO-driven permissions, and writes an append-only audit log on every query.

---

## 🏛️ Three pillars

| Pillar | What it means |
|---|---|
| 🔐 **Credentials never leave the gateway** | No DB URL on a laptop, ever. No tool returns one. No log line contains one. |
| 👤 **Identity end-to-end** | Every query traces SSO user → group → grant → audit row. |
| 📜 **Config-as-code** | Permissions live in YAML, reviewed by PR. No in-band admin UI, by design. |

---

## ✨ What's in the box

- 🤖 **MCP tool surface** — `list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain`, `get_query_history`.
- 🔑 **OIDC SSO** — Okta, Google Workspace, Entra, Authentik, Keycloak. Browser-flow login from the agent (no embedded browser needed).
- 🎯 **Read-only by default, writes opt-in per grant** — per-database least-privilege roles; a `query_write` grant permits data writes (INSERT/UPDATE/DELETE), never schema changes. Statement timeouts and row caps enforced at the DB *and* gateway layer.
- 📋 **Permissions in YAML** — group × server × database × action, with per-grant constraints (`require_reason`, `row_limit`, `statement_timeout_ms`, allow/deny schemas, time windows).
- 📊 **Synchronous audit log** — user, SQL, reason, row count, duration, outcome. Hot retention in Postgres, optional S3/GCS/Azure archive, OTLP/syslog/stdout sinks.
- 🐳 **Boring deployment** — `docker pull` + one YAML file + one Postgres.

---

## 🚧 Status

**v1.1.1 — stable.** In production use. Pull it: `docker pull ghcr.io/developerz-ai/db-mcp-gateway:1.1.1` — multi-arch (`linux/amd64`, `linux/arm64`). Targets: PostgreSQL and MongoDB (MySQL/MSSQL rejected at boot). See [`docs/deployment/releasing.md`](docs/deployment/releasing.md) for the compatibility policy.

---

## 🎯 Who Should Use This

**For Platform/SRE Teams:** Enable AI agent database access without credential exposure or compliance risk. Complete audit trail with SSO integration.

**For Backend Developers:** Query production databases safely using natural language. No database passwords on your laptop, every query attributed to your identity.

**For Data Analytics:** Self-service access to multiple databases (PostgreSQL, MySQL, MongoDB) through a single interface with built-in resource limits.

**For Security/Compliance:** Centralized database access control with user attribution, query logging, and enforceable constraints (timeouts, row limits, schema filtering).

---

## 💡 Key Use Cases

- **AI Agent Database Access:** Claude Code agents query production databases for debugging and analysis without ever handling database credentials
- **Analytics Without Direct Access:** Business analysts ask questions in natural language, gateway enforces read-only and resource limits automatically
- **Multi-Database Workflows:** AI agents query across PostgreSQL, MySQL, and MongoDB with unified security and audit trail
- **Production Debugging with Compliance:** On-call engineers investigate incidents with enforced reason logging and time limits

**[Read detailed use cases →](docs/use-cases.md)**

---

## ✨ Key Features

**🔐 Zero-Trust Security:** Database credentials never leave the gateway. No URLs, passwords, or connection strings reach AI agents or developer laptops.

**👤 Complete User Attribution:** Every query logged with SSO user identity, SQL statement, reason, timestamp, and results. Full compliance audit trail.

**🛡️ Built-in Safety:** Statement timeouts, row limits, read-only enforcement, and schema filtering prevent runaway queries and accidental data modification.

**📋 Git-Based Permissions:** Access control defined in YAML files, reviewed via PR, with complete change history. No admin UI to maintain.

**🤖 MCP-Native:** Purpose-built for AI agents with complete tool surface (list databases, describe schema, run queries, explain plans, query history).

**🏗️ Multi-Database:** Single gateway supports PostgreSQL, MySQL, and MongoDB with consistent security model and unified audit trail.

**[Read complete feature documentation →](docs/features.md)**

---

## 🚀 Quick links

| If you're… | Read |
|---|---|
| 💡 Trying to understand what this is | [`website/docs/initial-idea/01-overview.md`](website/docs/initial-idea/01-overview.md) |
| 🛠️ A developer whose org already runs it | [`docs/usage/first-query.md`](docs/usage/first-query.md) (5-min walkthrough) → [`docs/usage/claude-code.md`](docs/usage/claude-code.md) (reference) |
| 🏗️ A platform/SRE deploying it | [`docs/deployment/quickstart.md`](docs/deployment/quickstart.md) |
| 🤖 Adding it to a non-Claude MCP client | [`docs/usage/other-agents.md`](docs/usage/other-agents.md) |
| 📦 Cutting a release | [`docs/deployment/releasing.md`](docs/deployment/releasing.md) |
| 🚫 Wondering what it *won't* do | [`website/docs/initial-idea/10-non-goals.md`](website/docs/initial-idea/10-non-goals.md) |
| 🗺️ Tracking what's built vs planned | [`website/docs/initial-idea/11-roadmap.md`](website/docs/initial-idea/11-roadmap.md) |
| 📊 Performance benchmarks | [`docs/benchmarks.md`](docs/benchmarks.md) |
| ⚖️ vs alternatives | [`docs/comparison.md`](docs/comparison.md) |

---

## ⚡ One-minute mental model

```
┌─────────┐    MCP/HTTPS    ┌──────────────┐    pg wire    ┌──────────┐
│ agent   │ ──────────────▶ │   gateway    │ ────────────▶ │ target   │
│ (Claude │   bearer: jwt   │              │  ro role per  │  DBs     │
│  Code)  │ ◀────────────── │  authz+audit │ ◀──────────── │          │
└─────────┘   tool result   └──────┬───────┘   result rows └──────────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │ state DB     │
                            │ (sessions +  │
                            │  audit log)  │
                            └──────────────┘
```

---

## 🧱 Tech stack

| Concern | Choice |
|---|---|
| Language | Rust (stable) |
| Async runtime | tokio |
| HTTP | axum |
| DB driver | sqlx |
| Config | serde + YAML, validated at boot |
| State store | Postgres (co-deployed) |
| Distribution | OCI image — `ghcr.io/developerz-ai/db-mcp-gateway` |

---

## 📦 Pulling the image

Public on GHCR — no auth needed to pull:

```bash
docker pull ghcr.io/developerz-ai/db-mcp-gateway:latest
```

Pinned to a version (recommended in prod):

```bash
docker pull ghcr.io/developerz-ai/db-mcp-gateway:1.1.1
```

Multi-arch (amd64 + arm64). Built reproducibly from a `v*` git tag — see [`docs/deployment/releasing.md`](docs/deployment/releasing.md).

---

## 🤝 Adding it to Claude Code

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com
```

That's the whole client-side setup. First call triggers SSO. Walk through it end-to-end in [`docs/usage/first-query.md`](docs/usage/first-query.md), or jump to the full reference in [`docs/usage/claude-code.md`](docs/usage/claude-code.md).

---

## 📜 License

MIT. See [`LICENSE`](LICENSE).
