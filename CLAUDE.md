# CLAUDE.md

Self-hosted MCP gateway. AI agents get audited, SSO-gated, read-only DB access. Never holds a DB credential on the client side. Spec: `website/docs/initial-idea/`. Behavior change → update spec in the same PR.

Scoped rules load with their directory and bind like this file: [`src/CLAUDE.md`](src/CLAUDE.md) (layers, conventions), [`tests/CLAUDE.md`](tests/CLAUDE.md) (testing), [`bin/CLAUDE.md`](bin/CLAUDE.md) (every other command), [`.github/CLAUDE.md`](.github/CLAUDE.md) (CI), [`third_party/CLAUDE.md`](third_party/CLAUDE.md) (dependency graph).

## Non-negotiables (MUST)

1. DB credentials never leave the gateway. Not in responses, logs, errors, admin endpoints.
2. Every DB call traces to an SSO-verified identity → audit row.
3. Read-only by default. Writes require explicit per-grant opt-in AND a target-DB role with write privileges. Gateway will NOT provision write grants.
4. Audit is synchronous. Audit write fails → request fails. No best-effort audit.
5. Permissions in YAML (reviewed by PR) **or** via SSO-gated admin API (writes audited synchronously to `permissions_audit`). No in-band admin UI. See [12-dynamic-permissions](website/docs/initial-idea/12-dynamic-permissions.md).

## Response Rules

- **Execute.** No preamble, no "I'll start by…", no restating the task. Lead with the action or answer; reasoning after, only if non-obvious. Close with a 1–2 sentence summary, nothing else.
- **Parallel / read first.** Batch independent tool calls. Never speculate about a file you have not read.
- **Disagree.** Say when the requester is wrong; state the correction.
- **Terse.** Fragments OK. Drop articles, filler, hedging. Code, commands and paths verbatim — only prose gets compressed.

## Stack

Rust 2024: toolchain `1.96.0` (`rust-toolchain.toml`), MSRV `1.94.1` (`Cargo.toml`); deps pinned to latest stable at implementation time. tokio + axum (axum-server, rustls). sqlx `=0.9.1` for Postgres + MySQL (YugabyteDB YSQL rides the Postgres path), mongodb 3.10, redis 1.8 (Redis/Dragonfly). MCP: hand-rolled JSON-RPC over Streamable HTTP (POST; `GET /mcp` → 405) until an SDK stabilizes. Config: serde + serde-saphyr (not serde_yaml), validated at boot. State store: co-deployed Postgres (sessions, audit log, denylist); permissions store `pg` or `mysql`. GlitchTip errors, credential-scrubbed by `src/sentry_scrub/`. Prometheus `/metrics`. Images: GHCR **and** DOCR (`ghcr.io/developerz-ai/db-mcp-gateway`, `registry.digitalocean.com/developerz-ai/db-mcp-gateway`).

## Commands

| Task | Command |
|---|---|
| One-command setup (toolchain, deps, dev stack); `--hooks` enables git hooks | `bin/setup` |
| Dev stack up / down / reset / logs / ps; `psql state\|target`, `mongosh`, `mysql`, `ysqlsh` | `bin/dev <cmd>` |
| Full test (unit + integration) / unit only, no Docker / one module | `bin/test` / `bin/test --unit` / `bin/test --test it_db run_query_e2e::` |
| Format / only your changed `.rs` files | `bin/fmt` / `bin/fmt --changed` |
| Lint (fmt-check + clippy -D warnings) / fast lib + bins pass | `bin/lint` / `bin/lint --lib` |
| Reproduce CI locally / one-command check | `bin/ci` / `bin/check` |
| Your files against HEAD while the shared tree is mid-edit | `bin/snapshot-check <files…>` |
| Run the gateway from source (`--idp` adds Dex) | `bin/run` |

Secrets and local config: copy `.env.example` → `.env` (gitignored; shell env beats it).

## Concurrency

Many agents share one box. Build and test only through the `bin/` wrappers (`bin/test`, `bin/test-yugabyte`, `bin/lint`, `bin/check`, `bin/ci`): they queue on `.git/dbmcp-heavy.lock` (plus `.git/dbmcp-db.lock` for the shared dev DBs), print `queued: waiting for …`, and run under `heavy` when it is on `PATH`. Never raw `cargo test` against the DB suites. Never `bin/dev up`/`down` or `docker compose up` the dev stack while others use it — `up` under different env recreates containers. Stop `target-yugabyte` only with a 120 s grace (`docker stop -t 120`) — a SIGKILL wedges its tablets. `DBMCP_NO_QUEUE=1` opts out.

## Conventions

Idiomatic, boring, readable Rust; `clippy -D warnings` is the floor. Binding everywhere, detail in [`src/CLAUDE.md`](src/CLAUDE.md): typed errors with stable client codes; no `unwrap`/`expect` outside `src/main.rs` and tests; newtypes; derive `Debug`; borrow by default; one thing per function; `tracing`, not `println`; audit before response; per-DB pools; async end-to-end; cancellation safety; `src/` files ≤300 LOC; comment the *why*. Dependency graph: `Cargo.lock` is what ships — read [`third_party/CLAUDE.md`](third_party/CLAUDE.md) before changing a feature set or re-resolving the lock.

## Testing

Real DBs, never a mocked target; every tool-hitting integration test asserts its audit row; every `tests/it_db/` test declares its `world` isolation; constraint merge is proptested. Rules: [`tests/CLAUDE.md`](tests/CLAUDE.md).

## CI

GitHub Actions, GitHub-hosted runners only (public repo); `bin/ci` reproduces it locally. Jobs, caches, release lane and the rules for editing workflows: [`.github/CLAUDE.md`](.github/CLAUDE.md). Claude Code hooks: [`.claude/README.md`](.claude/README.md).

## Security review required

Touching any of these requires the `security review required` label on the PR: `src/auth/`, `src/authz/`, credential loading or storage, the audit write path, any new MCP tool, SQL execution (timeouts, row caps, cancellation). Reviewers look for: credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection / timeout bypass.

## Layout

```
src/                # layers: src/CLAUDE.md
migrations/         # state-DB schema (sqlx, Postgres); migrations-mysql/ = MySQL permissions store
tests/              # it_db/ (real DBs), it_offline/, it_global/ (process-global installs); standalone *.rs
benchmarks/         # load harness (feature-gated, never shipped)
config/             # example.yaml (commented), permissions.yml (deployable), dev.yaml
docs/               # internal notes, plans
website/docs/       # initial-idea/ = spec, usage/ = developer (additions are public-API changes), deployment/ = operator
bin/                # dev scripts
```

## NEVER

| Never | Because |
|---|---|
| Return a connection string, password, or role secret in any response, error, or log. | The client side never holds a DB credential (MUST #1). |
| Add an admin web UI for permissions. | Permissions change by reviewed YAML or the audited admin API only (MUST #5). |
| Mock the target DB in query-path tests. | A mock cannot prove timeouts, row caps or cancellation. |
| Skip the audit write for performance. | Audit is synchronous; a failed audit write fails the request (MUST #4). |
| Add a "service account" auth path without a permissions group + audit identity. | The shipped path is `service_accounts:` (spec 14): a static `dbmcp_svc_` bearer mapped to exactly one non-admin `permissions:` group, audited as `service:<name>`, YAML-only, no in-band mint/revoke — the one boot-validated exception to rule 2. Upstream headers (`x-dbmcp-run-id`, `x-dbmcp-on-behalf-of`) are attribution only, never authz. Any new service-auth mechanism keeps those four properties and lands with a spec 14 update. |
| Promote a request from one user's session to another. | The session identity is the audit subject (MUST #2). |
| Run as DB superuser. Per-DB read-only roles, full stop. | The per-DB role is the blast radius. |
| Serve a write path without an explicit per-grant opt-in **and** a target-DB role holding write privileges. | Read-only by default; the gateway will NOT provision write grants (MUST #3). |
| Force-push `main`. | History is auditable; a force-push rewrites what reviewers read. |
| `--no-verify` on commits — fix the hook. | The hook is the gate. |

## Context (not in code)

- Single-tenant. Two orgs sharing one install is unsupported.
- NOT building: BI tool, query builder, credential vault, SaaS, LLM, agent runtime.
- No git worktrees — work directly in this checkout. A task big enough to need subagents runs them as a team in this same checkout: split the work into disjoint pieces so no two agents touch the same files.
