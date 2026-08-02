# CLAUDE.md

Self-hosted MCP gateway. AI agents get audited, SSO-gated, read-only DB access. Never holds a DB credential on the client side.

Spec: `website/docs/initial-idea/`. Behavior change → update spec in the same PR.

## Response Rules

- Execute. No preamble. No "I'll start by…". No restating the task.
- Lead with action or answer. Reasoning after, only if non-obvious.
- Parallel tool calls when independent.
- Read before speculating.
- Disagree when user is wrong. State the correction.
- Terse. Fragments OK. Drop articles, filler, hedging.
- Code/commands/paths: verbatim. Only prose gets compressed.
- End-of-turn summary: 1–2 sentences. Nothing else.

## Non-negotiables (MUST)

1. DB credentials never leave the gateway. Not in responses, logs, errors, admin endpoints.
2. Every DB call traces to an SSO-verified identity → audit row.
3. Read-only by default. Writes require explicit per-grant opt-in AND a target-DB role with write privileges. Gateway will NOT provision write grants.
4. Audit is synchronous. Audit write fails → request fails. No best-effort audit.
5. Permissions in YAML (reviewed by PR) **or** via SSO-gated admin API (writes audited synchronously to `permissions_audit`). No in-band admin UI. See [12-dynamic-permissions](website/docs/initial-idea/12-dynamic-permissions.md).

## Stack

| Concern | Choice |
|---|---|
| Lang | Rust stable (pinned via `rust-toolchain.toml`) |
| Runtime | tokio |
| HTTP | axum |
| DB driver | sqlx (postgres-first) |
| MCP | hand-rolled JSON-RPC over HTTP+SSE → swap for SDK when one stabilizes |
| Config | serde + YAML, validated at boot |
| State store | Postgres (co-deployed) |
| Distribution | `ghcr.io/developerz-ai/db-mcp-gateway`, built+pushed by `.github/workflows/release.yml` on `v*` tags |

Deps pinned to latest stable at implementation time.

## Commands

| Task | Command |
|---|---|
| Bring up local dev stack (gateway state DB + a target Postgres) | `bin/dev up` |
| Tear down | `bin/dev down` |
| Logs | `bin/dev logs` |
| psql into state DB | `bin/dev psql state` |
| psql into example target DB | `bin/dev psql target` |
| Full test (unit + integration) | `bin/test` |
| Single test by pattern | `bin/test --test <name>` or `cargo test <pattern>` |
| Format | `bin/fmt` |
| Lint (fmt-check + clippy -D warnings) | `bin/lint` |
| Reproduce CI locally | `bin/ci` |
| Run the binary | `cargo run -- --config config/example.yaml` |
| Build release image locally | `docker build -t db-mcp-gateway:dev .` |

Secrets and local config: copy `.env.example` → `.env`. `.env` is gitignored.

## Layers

One reason to change per layer. Don't blur.

| Layer | Owns | Module |
|---|---|---|
| Transport | MCP framing, JSON-RPC, HTTP+SSE | `src/transport/` |
| Auth | OIDC, JWT, session cache | `src/auth/` |
| Authz | (user, groups, server, db, action) → allow + constraints | `src/authz/` |
| Tools | MCP tool dispatch | `src/tools/` |
| Exec | Per-DB pool, statement timeout, row cap, cancellation | `src/exec/` |
| Audit | Append-only writes, retention, archive, sinks | `src/audit/` |
| Config | YAML parse + validate + secrets resolve + hot reload | `src/config/` |
| State DB | Sessions, audit log, denylist | `src/state/` |

Files ≤300 LOC. Split by responsibility.

## Conventions

The bar: idiomatic, boring, readable Rust. No spaghetti, no premature abstraction. A function reads top to bottom without chasing state. Equally-correct options → pick the one easier to delete. `clippy -D warnings` is the floor, not the ceiling.

- Errors typed. `thiserror` for domain; `anyhow` only at `main.rs` boundary. Every client error has a stable code (see `website/docs/initial-idea/03-mcp-tools.md`).
- No `unwrap`/`expect` outside `main` and tests. Panic in hot path crashes every user. Propagate with `?`; branch with `match`/`if let`/`let ... else`.
- Newtype over bare primitives when a value has meaning (`RequestId(String)`, not `String`). Make illegal states unrepresentable — `enum` over contradictory `bool`+`Option`. Validate input into a type once at the edge; don't re-validate downstream.
- Derive, don't hand-roll (`Debug`, `Clone`, serde). Every public type derives `Debug` at minimum. Keep `pub` surface minimal.
- Borrow by default (`&str` over `String`, `&[T]` over `Vec<T>`). `.clone()` only when ownership must move — non-obvious clone gets a one-line `// why`. `Arc<T>` for shared read-only; add a lock only when you mutate shared state, keep the critical section tiny.
- Functions do one thing. Need "and" to describe it → split it. No premature abstraction: concrete first, introduce a trait when the **second** impl arrives (e.g. `DbAdapter`). Iterator chains over manual index loops where they read clearer.
- `tracing`, not `println`. Every tool dispatch is a span with `request_id`, `user`, `server`, `database`.
- Audit write commits **before** success response goes out. Two-phase commit with state DB.
- Per-DB pools, sized by config. Never one global pool. Never share a pool across `(server, database)`.
- Async end-to-end. No `std::sync::Mutex` on request path — use `tokio::sync`. No `block_on`, no blocking I/O in async fns (offload with `spawn_blocking`). Never hold a `std::sync` guard across `.await`. Slow query on DB A must never block DB B. One noisy user must not starve others.
- Cancellation safety. Agent disconnect → tokio task dropped → `pg_cancel_backend` → audit row `outcome: cancelled`. Test it; easy to write code that holds the conn until the query finishes anyway.
- No backwards-compat shims pre-v1.
- Comment the non-obvious *why*, never the *what*. Rename until code doesn't need the *what*. `///` on public items whose contract isn't obvious from the signature. Architecture decisions go in `website/docs/initial-idea/`, not code comments.

## Testing

- Unit: pure logic (authz evaluation, config validation, SQL rewriting). No real DB.
- Integration: gateway booted against real Postgres (CI service container). Real MCP requests over HTTP.
- Property tests for authz constraint-merge (`proptest`) — most restrictive value wins, always.
- NEVER mock the target DB in query-path tests.
- Every integration test that hits a tool asserts an audit row exists. Tool failed authz → audit row with `outcome: forbidden`.

## CI

GitHub Actions on Blacksmith — `blacksmith-2vcpu-ubuntu-2404` default. Postgres as a service. Workflows in `.github/workflows/`. `bin/ci` reproduces it locally.

- CI runs on Blacksmith (`blacksmith-2vcpu-ubuntu-2404`). Every workflow declares a `concurrency` group with cancel-in-progress, and every job sets `timeout-minutes`. The CI image job pushes a moving tag (Image Updater newest-wins, so `cancel-in-progress: true` is deliberate); the release workflow is hard `cancel-in-progress: false`.

## Security review required

Touching any of these requires a `(security review required)` label on the PR:

- `src/auth/`, `src/authz/`
- Credential loading or storage
- Audit write path
- Any new MCP tool
- SQL execution (timeouts, row caps, cancellation)

Reviewers look for: credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection / timeout bypass.

## Layout

```
src/
  main.rs           # entry, signals, graceful shutdown
  config/           # YAML schema, validation, secrets, hot reload
  transport/        # MCP over HTTP+SSE
  auth/             # OIDC, JWT, sessions
  authz/            # grant evaluation, constraint merge
  tools/            # MCP tool impls
  exec/             # per-DB pools, query exec, timeouts, row caps
  audit/            # writer, pruner, archive, sinks
  state/            # state DB queries, migrations
  errors.rs         # typed error enum
config/example.yaml # commented example
website/docs/
  initial-idea/     # canonical spec
  usage/            # developer-facing
  deployment/       # operator-facing
bin/                # dev/test/lint/ci helpers
docker-compose.dev.yml
```

## NEVER

- Return a connection string, password, or role secret in any response, error, or log.
- Add an admin web UI for permissions.
- Mock the target DB in query-path tests.
- Skip the audit write for performance.
- Add a "service account" auth path without a permissions group + audit identity.
- Promote a request from one user's session to another.
- Run as DB superuser. Per-DB read-only roles, full stop.
- Force-push `main`.
- `--no-verify` on commits — fix the hook.

## Context (not in code)

- Single-tenant. Two orgs sharing one install is unsupported.
- Distribution is GHCR (public, free, no Docker Hub rate limits). Helm chart on roadmap.
- NOT building: BI tool, query builder, credential vault, SaaS, LLM, agent runtime.

## Docs

- `website/docs/initial-idea/` — spec, numbered. `00-seed.md` = original framing.
- `website/docs/usage/` — developer-facing. Treat additions as public-API changes.
- `website/docs/deployment/` — operator-facing.
- Architecture decisions land in the spec, not in code comments.

## Note

Do not use git worktrees — work directly in this checkout. If a task is big enough to need subagents, run them as a team in this same checkout: split the work into disjoint pieces so no two agents touch the same files.
