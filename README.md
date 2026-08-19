<p align="center">
  <img src="https://raw.githubusercontent.com/developerz-ai/db-mcp-gateway/main/website/static/img/logo.png" alt="db-mcp-gateway" width="200">
</p>

<h1 align="center">db-mcp-gateway</h1>

<p align="center"><strong>Your AI agent needs to read the production database. The connection string is the one thing you cannot hand it.</strong></p>

Give an agent a database URL and that credential now lives on a laptop, in a
config file, in shell history, and in whatever the agent decides to echo back.
Rotating it means finding every copy. And every query it runs is attributed to
nobody.

**db-mcp-gateway holds the credential instead.** It is a self-hosted MCP server
your team deploys once. Developers point their agent at one URL. The gateway
authenticates them through the SSO you already run, checks each query against
permissions reviewed by pull request, and commits an append-only audit row
before any result goes back.

## Install

**v1.1.1 — stable, in production use.** One image, one YAML file, one Postgres:

```bash
docker pull ghcr.io/developerz-ai/db-mcp-gateway:1.1.1
```

Public on GHCR, no auth needed to pull. Multi-arch (`linux/amd64`,
`linux/arm64`), built reproducibly from a `v*` git tag. `:latest` tracks the
newest release; pin the version in production. Compatibility policy in
[`website/docs/deployment/releasing.md`](website/docs/deployment/releasing.md),
deployment in [`website/docs/deployment/quickstart.md`](website/docs/deployment/quickstart.md).

Client side, that is the whole setup:

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com
```

The first call triggers SSO in a real browser — no embedded webview, no token
pasting. Walk through it end to end in
[`website/docs/usage/first-query.md`](website/docs/usage/first-query.md), or use
another MCP client via
[`website/docs/usage/other-agents.md`](website/docs/usage/other-agents.md).

---

## Three pillars

| Pillar | What it means |
|---|---|
| **Credentials never leave the gateway** | No DB URL on a laptop, ever. No tool returns one. No log line contains one. |
| **Identity end-to-end** | Every query traces SSO user → group → grant → audit row. |
| **Config-as-code** | Permissions live in YAML, reviewed by PR. No in-band admin UI, by design. |

---

## Supported databases

"MySQL" means two unrelated things here, so both are stated once, in one table.
**Query targets** are what an agent can read through the gateway. The
**permissions store** is where the gateway keeps its own grant metadata — an
agent never touches it.

| | PostgreSQL | MongoDB | MySQL | MSSQL |
|---|---|---|---|---|
| **Query target** — agents can query it | yes | yes | no — [rejected at boot](website/docs/usage/multi-db.md) | no — rejected at boot |
| **Permissions store** — gateway's own state | yes | no, by design | resolver path only, [no admin API](website/docs/deployment/admin-api.md) | no |

A `server.kind` of `mysql` or `mssql` refuses to start rather than booting
clean and failing every query, so a wrong config is caught at deploy time and
not by a user. MySQL and MSSQL query adapters are on the roadmap.

**Performance:** we publish no benchmark numbers. We removed the ones we had
because nobody had measured them — [here is what happened and how to measure
it yourself](website/docs/benchmarks.md).

---

## What it does

- **MCP tool surface** — `list_servers`, `list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain`.
- **OIDC SSO** — Okta, Google Workspace, Entra, Authentik, Keycloak. Browser-flow login from the agent.
- **Read-only by default, writes opt-in per grant** — per-database least-privilege roles; a `query_write` grant permits data writes (INSERT/UPDATE/DELETE), never schema changes. Statement timeouts and row caps enforced at the DB *and* gateway layer.
- **Permissions in YAML** — group × server × database × action, with per-grant constraints (`require_reason`, `row_limit`, `statement_timeout_ms`, allow/deny schemas, time windows). Reviewed by PR, with the full change history git already gives you.
- **Synchronous audit log** — user, SQL, reason, row count, duration, outcome. The write commits *before* the response is sent; if it fails, the request fails. Hot retention in Postgres, optional S3/GCS/Azure archive, OTLP/syslog/stdout sinks.
- **Boring deployment** — `docker pull`, one YAML file, one Postgres. No agent runtime, no query builder, no credential vault to operate.

[Complete feature documentation →](website/docs/features.md)

---

## Who it's for

| If you are… | What you get |
|---|---|
| **Platform / SRE** | Agent database access without credential exposure, and one place to revoke it |
| **A backend developer** | Production queries for debugging with no password on your laptop, every one attributed to you |
| **Data / analytics** | Self-service access across every supported target through one interface, with resource limits already enforced |
| **Security / compliance** | Per-query SSO attribution, enforced reason logging, and an audit trail you did not have to build |

[Detailed use cases →](website/docs/use-cases.md)

---

## How it works

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

## Docs

| If you're… | Read |
|---|---|
| Trying to understand what this is | [`website/docs/initial-idea/01-overview.md`](website/docs/initial-idea/01-overview.md) |
| A developer whose org already runs it | [`website/docs/usage/first-query.md`](website/docs/usage/first-query.md) (5-min walkthrough) → [`website/docs/usage/claude-code.md`](website/docs/usage/claude-code.md) (reference) |
| A platform/SRE deploying it | [`website/docs/deployment/quickstart.md`](website/docs/deployment/quickstart.md) |
| Adding it to a non-Claude MCP client | [`website/docs/usage/other-agents.md`](website/docs/usage/other-agents.md) |
| Cutting a release | [`website/docs/deployment/releasing.md`](website/docs/deployment/releasing.md) |
| Wondering what it *won't* do | [`website/docs/initial-idea/10-non-goals.md`](website/docs/initial-idea/10-non-goals.md) |
| Tracking what's built vs planned | [`website/docs/initial-idea/11-roadmap.md`](website/docs/initial-idea/11-roadmap.md) |
| Asking about performance | [`website/docs/benchmarks.md`](website/docs/benchmarks.md) |
| Comparing against alternatives | [`website/docs/comparison.md`](website/docs/comparison.md) |

---

## Built with

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

## License

MIT. See [`LICENSE`](LICENSE).
