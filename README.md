# db-mcp-gateway 🛡️

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

## 🚀 Quick links

| If you're… | Read |
|---|---|
| 💡 Trying to understand what this is | [`docs/initial-idea/01-overview.md`](docs/initial-idea/01-overview.md) |
| 🛠️ A developer whose org already runs it | [`docs/usage/first-query.md`](docs/usage/first-query.md) (5-min walkthrough) → [`docs/usage/claude-code.md`](docs/usage/claude-code.md) (reference) |
| 🏗️ A platform/SRE deploying it | [`docs/deployment/quickstart.md`](docs/deployment/quickstart.md) |
| 🤖 Adding it to a non-Claude MCP client | [`docs/usage/other-agents.md`](docs/usage/other-agents.md) |
| 📦 Cutting a release | [`docs/deployment/releasing.md`](docs/deployment/releasing.md) |
| 🚫 Wondering what it *won't* do | [`docs/initial-idea/10-non-goals.md`](docs/initial-idea/10-non-goals.md) |
| 🗺️ Tracking what's built vs planned | [`docs/initial-idea/11-roadmap.md`](docs/initial-idea/11-roadmap.md) |

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
