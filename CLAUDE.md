# CLAUDE.md

Self-hosted MCP gateway. AI agents get audited, SSO-gated, read-only DB access. Never holds a DB credential on the client side. Spec: `website/docs/initial-idea/`. Behavior change → update spec in the same PR.

## Non-negotiables (MUST)

1. DB credentials never leave the gateway. Not in responses, logs, errors, admin endpoints.
2. Every DB call traces to an SSO-verified identity → audit row.
3. Read-only by default. Writes require explicit per-grant opt-in AND a target-DB role with write privileges. Gateway will NOT provision write grants.
4. Audit is synchronous. Audit write fails → request fails. No best-effort audit.
5. Permissions in YAML (reviewed by PR) **or** via SSO-gated admin API (writes audited synchronously to `permissions_audit`). No in-band admin UI. See [12-dynamic-permissions](website/docs/initial-idea/12-dynamic-permissions.md).

## Response Rules

| Rule | Meaning |
|---|---|
| Execute | No preamble, no "I'll start by…", no restating the task. Lead with the action or the answer; reasoning after, only if non-obvious. Close with a 1–2 sentence summary, nothing else. |
| Parallel / read first | Batch independent tool calls. Never speculate about a file you have not read. |
| Disagree | Say when the requester is wrong; state the correction. |
| Terse | Fragments OK. Drop articles, filler, hedging. Code, commands and paths: verbatim — only prose gets compressed. |

## Stack

| Concern | Choice |
|---|---|
| Lang | Rust 2024 — toolchain channel `1.96.0` (`rust-toolchain.toml`: rustfmt + clippy), MSRV `1.94.1` (`Cargo.toml`); deps pinned to latest stable at implementation time |
| Runtime / HTTP | tokio; axum (+ axum-server, rustls) |
| DB driver | sqlx 0.9 (`=0.9.1`; 0.9.0 clobbers the unnamed statement) — Postgres + MySQL (YugabyteDB YSQL rides the Postgres path, CI-tested); mongodb 3.10 for the Mongo target; redis 1.8 for the Redis/Dragonfly target |
| MCP | hand-rolled JSON-RPC over Streamable HTTP (POST; `GET /mcp` → 405) → swap for SDK when one stabilizes |
| Config | serde + serde-saphyr (not serde_yaml), validated at boot |
| State store | Postgres (co-deployed): sessions, audit log, denylist. Permissions store `pg` (`src/state/permissions/pg.rs`) or `mysql` (`src/state/permissions/mysql/`) |
| Error tracking | GlitchTip (Sentry protocol), credential-scrubbed by `src/sentry_scrub/` |
| Metrics | `metrics` + Prometheus exporter on `/metrics` |
| Distribution | `ghcr.io/developerz-ai/db-mcp-gateway` **and** `registry.digitalocean.com/developerz-ai/db-mcp-gateway`: `ci.yml` pushes `sha-<7>` + `main` on every `main` push; `release.yml` re-tags that tested manifest on a `v*` tag with semver + `:latest` |

## Commands

| Task | Command |
|---|---|
| One-command setup (toolchain, deps, dev stack) | `bin/setup` |
| Dev stack up / down / reset / logs / container status | `bin/dev up` / `bin/dev down` / `bin/dev reset` / `bin/dev logs` / `bin/dev ps` |
| psql — state DB / target DB | `bin/dev psql state` / `bin/dev psql target` |
| mongosh — target Mongo | `bin/dev mongosh` |
| mysql — permissions store | `bin/dev mysql` |
| ysqlsh — target YugabyteDB (compose profile `yugabyte`) | `bin/dev ysqlsh` |
| Full test (unit + integration; cargo-nextest when installed, else `cargo test`) | `bin/test` |
| Postgres query-path suite against YugabyteDB (starts `state-db` + `target-yugabyte`, nextest profile `yugabyte`) | `bin/test-yugabyte` |
| Single test by pattern (several filters OK, no `--` needed) | `bin/test --test <binary> <module>::` (e.g. `bin/test --test it_db run_query_e2e:: explain_e2e::`) |
| Format / only your changed `.rs` files (vs `origin/main` + untracked) | `bin/fmt` / `bin/fmt --changed` |
| Lint (fmt-check + clippy -D warnings) / fast lib + bins pass | `bin/lint` / `bin/lint --lib` |
| Check your files against HEAD while the shared tree is mid-edit (own target dir; `-- <cmd>` overrides clippy + unit tests) | `bin/snapshot-check <files…> [-- cargo test --test it_offline <filter>]` |
| Regenerate nextest's run-alone list after adding/removing `#[serial_test::serial(world)]` | `bin/regen-serial` |
| Validate `deploy/` (promtool, helm lint, kubeconform; Docker only) | `bin/check-deploy` |
| Reproduce CI locally / one-command check (2 build jobs by default; `CARGO_BUILD_JOBS=$(nproc) bin/check` on a dedicated box) | `bin/ci` / `bin/check` |
| Assert scrubber regex features in the shipping graph | `bin/check-scrub-features` |
| Mint a static service bearer token | `bin/mint-service-token <name>` |
| Run the gateway from source (dev stack + committed `config/dev.yaml`; `--idp` adds Dex) | `bin/run` |
| Seed the demo `shop` DB on the dev target | `bin/seed` |
| One MCP tool call as the dev service token | `bin/mcp-call <tool> '<json>'` (`--list` for tools) |
| Unit loop, no Docker | `bin/test --unit` |
| One-command demo (Docker only, no Rust) | `cd examples/demo && docker compose up -d` |
| Enable git hooks (pre-commit fmt + scans; pre-push clippy + unit) | `bin/setup --hooks` |
| Build release image locally | `docker build -t db-mcp-gateway:dev .` |

Secrets and local config: copy `.env.example` → `.env`. `.env` is gitignored; shell env beats `.env`.

**Concurrency.** Many agents share one box. Build and test only through the `bin/` wrappers (`bin/test`, `bin/test-yugabyte`, `bin/lint`, `bin/check`, `bin/ci`): they queue on `.git/dbmcp-heavy.lock` (plus `.git/dbmcp-db.lock` for the shared dev DBs), print `queued: waiting for …`, and run under `heavy` when it is on `PATH`. Never raw `cargo test` against the DB suites. Never `bin/dev up`/`down` or `docker compose up` the dev stack while others use it — `up` under different env recreates containers. Stop `target-yugabyte` only with a 120 s grace (`docker stop -t 120`; compose uses its `stop_grace_period`) — a SIGKILL wedges its tablets. To verify your own files while others' edits break the build, `bin/snapshot-check` (HEAD + your files, separate target dir, `--slot` to run beside another agent). `DBMCP_NO_QUEUE=1` opts out.

## Layers

One reason to change per layer. Don't blur.

| Layer | Owns | Module |
|---|---|---|
| Transport | HTTP routes, request id, budgets/timeouts, OAuth handlers, admin API (MCP framing types in `src/mcp/`) | `src/transport/`, `src/mcp/` |
| Auth | OIDC, JWT, session cache, service tokens, OAuth state (`src/auth/oauth/`) | `src/auth/` |
| Authz | (user, groups, server, db, action) → allow + constraints; per-replica cache, admin commits reach other replicas via LISTEN/NOTIFY, SIGHUP reloads YAML | `src/authz/` |
| Tools | MCP tool dispatch | `src/tools/` |
| Exec | Per-DB pool, statement timeout, row cap, cancellation | `src/exec/` |
| Audit | Append-only writes, retention, archive, sinks | `src/audit/` |
| Config | YAML parse + validate + secrets resolve + hot reload | `src/config/` |
| State DB | Sessions, audit log, denylist, permissions store | `src/state/` |

## Conventions

The bar: idiomatic, boring, readable Rust. No spaghetti, no premature abstraction. A function reads top to bottom without chasing state. Equally-correct options → pick the one easier to delete. `clippy -D warnings` is the floor, not the ceiling.

| Rule | Meaning |
|---|---|
| Typed errors | `thiserror` for domain; `anyhow` only at the boot boundary (`src/main.rs`, `src/startup/`, `src/cli/`): those errors print on exit and never reach a client. Every client error has a stable code (see `website/docs/initial-idea/03-mcp-tools.md`). |
| No panics | No `unwrap`/`expect` outside `src/main.rs` and tests — a panic in a hot path crashes every user. Propagate with `?`; branch with `match`/`if let`/`let ... else`. |
| Newtypes | Newtype over bare primitives when a value has meaning (`RequestId(String)`, not `String`). Make illegal states unrepresentable — `enum` over contradictory `bool`+`Option`. Validate input into a type once at the edge; don't re-validate downstream. |
| Derive | Derive, don't hand-roll (`Debug`, `Clone`, serde). Every public type derives `Debug` at minimum. Keep the `pub` surface minimal. |
| Borrow by default | `&str` over `String`, `&[T]` over `Vec<T>`. `.clone()` only when ownership must move — a non-obvious clone gets a one-line `// why`. `Arc<T>` for shared read-only; add a lock only when you mutate shared state, keep the critical section tiny. |
| One thing per function | Need "and" to describe it → split it. No premature abstraction: concrete first, introduce a trait when the **second** impl arrives (e.g. `DbAdapter`). Iterator chains over manual index loops where they read clearer. |
| Tracing | `tracing`, not `println`. Every tool dispatch is a span with `request_id`, `user`, `server`, `database`. |
| Audit before response | Two-phase: an intent row commits before any target call; the completion row commits **before** the response goes out; a missing completion is reaped as `abandoned`. Audit write fails → `audit_unavailable`, never a silent success. |
| Per-DB pools | Sized by config (`pool:` on server/database). Lazy (min 0, idle 5 min), replaced on credential rejection or reload. Two pools per `(server, database)` when `write_role` is set (read tier runs as `role` in a read-only transaction, write tier as `write_role`). Never one global pool. Never share a pool across `(server, database)`. |
| Async end-to-end | No `std::sync::Mutex` on the request path — use `tokio::sync`. No `block_on`, no blocking I/O in async fns (offload with `spawn_blocking`). Never hold a `std::sync` guard across `.await`. A slow query on DB A must never block DB B. One noisy user must not starve others. |
| Cancellation safety | Agent disconnect → tokio task dropped → `pg_cancel_backend` → audit row `outcome: cancelled`. Test it; easy to write code that holds the conn until the query finishes anyway. |
| Size | Files under `src/` ≤300 LOC — split by responsibility. `tests/` and `benchmarks/` are exempt (one file per scenario reads better); keep each test fn focused. No backwards-compat shims pre-v1. |
| Comments | Comment the non-obvious *why*, never the *what*. Rename until code doesn't need the *what*. `///` on public items whose contract isn't obvious from the signature. Architecture decisions go in `website/docs/initial-idea/`, not code comments. |
| Dependency graph | `Cargo.lock` is what ships, not what compiles. Read [`third_party/CLAUDE.md`](third_party/CLAUDE.md) before changing a feature set or re-resolving the lock. |

## Testing

| Kind | Rule |
|---|---|
| Unit + property | Pure logic (authz evaluation, config validation, SQL rewriting), no real DB. Authz constraint-merge (`proptest`): most restrictive value wins, always. |
| Integration | Gateway booted against real Postgres (CI service container). Real MCP requests over HTTP. |
| Audit | Every integration test that hits a tool asserts an audit row exists. Tool failed authz → audit row with `outcome: forbidden`. |
| Isolation | Every `tests/it_db/` test declares `#[serial_test::serial(world)]` (table-wide side effect: reaper/pruner/GC sweep, cap seeding, global counts) or `#[serial_test::parallel(world)]` — the suites share one process under `cargo test`. Enforced by `it_offline::isolation_guard`. |

## CI

GitHub Actions, GitHub-hosted runners only (public repo); `bin/ci` reproduces it locally. Job table, caches and the rules for editing workflows: [`.github/CLAUDE.md`](.github/CLAUDE.md). Claude Code hooks: [`.claude/README.md`](.claude/README.md).

## Security review required

Touching any of these requires the `security review required` label on the PR: `src/auth/`, `src/authz/`, credential loading or storage, the audit write path, any new MCP tool, SQL execution (timeouts, row caps, cancellation). Reviewers look for: credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection / timeout bypass.

## Layout

```
src/
  main.rs           # entry, signals, graceful shutdown
  lib.rs            # library root the integration tests drive
  startup/          # boot helpers (tracing, state DB, app state, serve) + background tasks
  sentry_scrub/     # credential scrubbing for GlitchTip
  config/           # YAML schema, validation, secrets, hot reload
  mcp/              # JSON-RPC envelope, MCP payloads + tool names (shared by transport and tools)
  transport/        # MCP over Streamable HTTP, OAuth routes, admin API
  auth/             # OIDC, JWT, sessions, service tokens
  authz/            # grant evaluation, constraint merge
  tools/            # MCP tool impls
  exec/             # per-DB pools, query exec, timeouts, row caps (pg/, mongo/, redis/)
  audit/            # writer, pruner, archive, sinks
  state/            # state DB queries, permissions store (pg.rs, permissions/mysql/); no central errors.rs — each layer owns its typed error
migrations/         # state-DB schema (sqlx, Postgres); migrations-mysql/ = MySQL permissions store
tests/              # integration tests, one binary per group dir: it_db/ (real DBs, never a mocked target DB), it_offline/, it_global/ (process-global installs); brief_rows.rs, doc_drift.rs standalone
benchmarks/         # load harness (feature-gated, never shipped)
config/             # example.yaml (commented), permissions.yml (deployable)
docs/               # internal notes (security QA)
website/docs/       # initial-idea/ = spec (00-seed.md = original framing), usage/ = developer (additions are public-API changes), deployment/ = operator
bin/                # setup/dev/test/fmt/lint/ci/check helpers
docker-compose.dev.yml
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
- Distribution is GHCR + DOCR (public, free, no Docker Hub rate limits). Helm chart on roadmap.
- NOT building: BI tool, query builder, credential vault, SaaS, LLM, agent runtime.
- No git worktrees — work directly in this checkout. A task big enough to need subagents runs them as a team in this same checkout: split the work into disjoint pieces so no two agents touch the same files.
