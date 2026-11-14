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
| Lang | Rust 2024 — toolchain channel `1.96.0` (`rust-toolchain.toml`: rustfmt + clippy), MSRV `1.88` (`Cargo.toml`); deps pinned to latest stable at implementation time |
| Runtime / HTTP | tokio; axum (+ axum-server, rustls) |
| DB driver | sqlx 0.8 — Postgres + MySQL; mongodb 3.7 for the Mongo target |
| MCP | hand-rolled JSON-RPC over Streamable HTTP (POST; `GET /mcp` → 405) → swap for SDK when one stabilizes |
| Config | serde + serde-saphyr (not serde_yaml), validated at boot |
| State store | Postgres (co-deployed): sessions, audit log, denylist. Permissions store `pg` (`src/state/permissions/pg.rs`) or `mysql` (`src/state/permissions/mysql/`) |
| Error tracking | GlitchTip (Sentry protocol), credential-scrubbed by `src/sentry_scrub/` |
| Metrics | `metrics` + Prometheus exporter on `/metrics` |
| Distribution | `ghcr.io/developerz-ai/db-mcp-gateway` **and** `registry.digitalocean.com/developerz-ai/db-mcp-gateway` — `.github/workflows/ci.yml` (`build` + `merge`) pushes per-arch images and the multi-arch manifest to both registries on pushes to `main`; `.github/workflows/release.yml` pushes the `v*` tag builds (semver + `:latest` + GitHub release) |

## Commands

| Task | Command |
|---|---|
| One-command setup (toolchain, deps, dev stack) | `bin/setup` |
| Dev stack up / down / reset / logs / container status | `bin/dev up` / `bin/dev down` / `bin/dev reset` / `bin/dev logs` / `bin/dev ps` |
| psql — state DB / target DB | `bin/dev psql state` / `bin/dev psql target` |
| mongosh — target Mongo | `bin/dev mongosh` |
| mysql — permissions store | `bin/dev mysql` |
| Full test (unit + integration; cargo-nextest when installed, else `cargo test`) | `bin/test` |
| Single test by pattern | `bin/test --test <name>` or `cargo test <pattern>` |
| Format | `bin/fmt` |
| Lint (fmt-check + clippy -D warnings) | `bin/lint` |
| Reproduce CI locally / one-command check | `bin/ci` / `bin/check` |
| Assert scrubber regex features in the shipping graph | `bin/check-scrub-features` |
| Mint a static service bearer token | `bin/mint-service-token <name>` |
| Run the binary (after `bin/dev up`; `config/example.yaml` is a reference — its `vault:` refs abort boot) | write the minimal `config.yml` from `website/docs/deployment/quickstart.md#run-it-locally`, then `TLS_DISABLED=true OIDC_ISSUER=http://localhost:5556 OIDC_CLIENT_ID=dev ALLOW_INSECURE_SIGNING_KEY=true TARGET_DB_PASSWORD=app-dev-only cargo run -- --config config.yml` |
| Build release image locally | `docker build -t db-mcp-gateway:dev .` |

Secrets and local config: copy `.env.example` → `.env`. `.env` is gitignored.

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
| Typed errors | `thiserror` for domain; `anyhow` only at the `src/main.rs` boundary. Every client error has a stable code (see `website/docs/initial-idea/03-mcp-tools.md`). |
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
| Size | Files ≤300 LOC. Split by responsibility. No backwards-compat shims pre-v1. |
| Comments | Comment the non-obvious *why*, never the *what*. Rename until code doesn't need the *what*. `///` on public items whose contract isn't obvious from the signature. Architecture decisions go in `website/docs/initial-idea/`, not code comments. |
| Dependency graph | `Cargo.lock` is what ships, not what compiles. Read §Dependency graph before changing a feature set or re-resolving the lock. |

### Dependency graph

- **An optional dependency enters `Cargo.lock` as soon as an enabled feature references it — even weakly (`dep?/feat`).** sqlx's `migrate`/`json`/`chrono`/`uuid` features each reference `sqlx-sqlite?/…`, so the SQLite driver landed in the lock with `libsqlite3-sys` 0.30.1 (RUSTSEC-2026-0459) while never being compiled: `cargo tree -i libsqlite3-sys` was empty before the fix, only the lock entry was vulnerable. `cargo audit` reads the lock, so it flags crates this project never builds.
- **`third_party/sqlx-sqlite-noop` stands in for that driver** — a no-op crate named `sqlx-sqlite`, patched in via `[patch.crates-io]` in the root `Cargo.toml` and declared as a workspace member, because `cargo chef` restores only workspace members into the Docker builder stage. Bump its version in lockstep with sqlx: a version that no longer satisfies sqlx's requirement makes cargo warn `patch not used`, the real driver returns to the lock, and the advisory returns with it. The root manifest pins `sqlx = "=0.8.6"` exactly for that reason — `cargo update` cannot move sqlx off the version the stub satisfies, so the two are bumped together in one commit, never apart.
- **The repo is a two-crate workspace** — the root package plus that stub — but the stub is a workspace member, **not** a default member. With a root package present and no `default-members`, Cargo's default members are the root package alone (Cargo Book, §"The default-members field": "When unspecified, the root package will be used"), so a plain `cargo build` from the root never compiles the stub. Only a workspace-wide package selection (`cargo build --workspace`, or its `--all` alias) builds it, and no gate passes either — `bin/lint`, `bin/ci` and `ci.yml` all run root-package-only commands (`cargo clippy --all-targets --all-features`, `cargo test --all-targets --all-features`; `--all-targets`/`--all-features` select targets and features, not workspace members). `bin/lint`'s `cargo fmt --all` formats the stub but never compiles it. The stub's whole job is to exist: in the lock, and in the Docker builder stage, where `cargo chef` restores it.
- **Re-resolve narrowly.** `cargo update -p sqlx --precise 0.8.6` is not the narrowest way to re-resolve here — it collapses windows-sys 0.48.0/0.59.0 into 0.61.2, whereas a plain re-resolve (`cargo metadata`) produced a lock diff with zero version changes to unrelated crates.

## Testing

| Kind | Rule |
|---|---|
| Unit + property | Pure logic (authz evaluation, config validation, SQL rewriting), no real DB. Authz constraint-merge (`proptest`): most restrictive value wins, always. |
| Integration | Gateway booted against real Postgres (CI service container). Real MCP requests over HTTP. |
| Audit | Every integration test that hits a tool asserts an audit row exists. Tool failed authz → audit row with `outcome: forbidden`. |

## CI

GitHub Actions on GitHub-hosted runners — `ubuntu-latest` default (`ubuntu-24.04-arm` for arm64), with Postgres, target Postgres, MySQL and Mongo as services. Workflows in `.github/workflows/`; `bin/ci` reproduces them locally.

| Job | Does |
|---|---|
| `fmt` | `cargo fmt --check`; every action pinned to a 40-hex SHA |
| `changes` | path filter: docs-only PRs (`website/**`, `docs/**`, `*.md`) skip `clippy`/`test` via per-job `if:` (a skipped required job reads as passed) |
| `clippy` | `clippy -D warnings` (all-targets + release cfg, `--profile ci`) + `bin/check-scrub-features` |
| `test` | `cargo nextest run --profile ci --cargo-profile ci --all-targets --all-features` against the service containers; JUnit uploaded (`.config/nextest.toml`) |
| `audit` | `cargo audit --ignore RUSTSEC-2023-0071` |
| `secret-scan` | advisory — `git grep -nE` over every tracked file for `dbmcp_svc_[0-9a-f]{64}`; exempt paths: `tests/**`, `website/**`, `config/example.yaml`, `.github/**`, `src/config/yaml/**` |
| `public-tree` | `cargo test --test public_tree` on every PR, docs-only included (no `changes` gate): no internal host, private repo, private CI provider, setup-mode name or home path in any tracked file |
| `weekly` (`weekly.yml`) | Mondays: `cargo audit` on `main` + `cargo update --dry-run` report |
| `build` + `merge` | on `main`: per-arch image → multi-arch manifest, pushed to GHCR **and** DOCR |

Every workflow declares a `concurrency` group, and every job sets `timeout-minutes` (~2× measured p95: clippy 15, test 20, small jobs 5, CI image build 30; the release per-arch build gets 60 to cover a cold compile). Each Rust job keeps its own `Swatinem/rust-cache` key — never a shared key: it made `test` restore clippy's check-only artifacts and rebuild the graph. `ci.yml` cancels superseded **PR** runs only — pushes to `main` get a per-SHA concurrency group and never cancel (a shared group would still drop a *pending* run when a third merge queues), because the Image Updater pins the short SHA, so cancelling the first of two closely-landed merges would leave that commit with no image at its tag (`main` is a moving convenience tag). `release.yml`, `pages.yml` (a half-applied Pages deploy) and `weekly.yml` are hard `cancel-in-progress: false`. Public repo, so GitHub-hosted runners only.

## Security review required

Touching any of these requires a `(security review required)` label on the PR: `src/auth/`, `src/authz/`, credential loading or storage, the audit write path, any new MCP tool, SQL execution (timeouts, row caps, cancellation). Reviewers look for: credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection / timeout bypass.

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
  exec/             # per-DB pools, query exec, timeouts, row caps (pg/, mongo/)
  audit/            # writer, pruner, archive, sinks
  state/            # state DB queries, permissions store (pg.rs, permissions/mysql/); no central errors.rs — each layer owns its typed error
migrations/         # state-DB schema (sqlx, Postgres); migrations-mysql/ = MySQL permissions store
tests/              # integration tests — real DBs, never a mocked target DB
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
| Add a "service account" auth path without a permissions group + audit identity. | The shipped path is `service_accounts:` (spec 14, `src/auth/service_token.rs`): a static `dbmcp_svc_` bearer mapped to exactly one `permissions:` group, audited as `service:<name>`, boot-gated off the admin group, with no in-band mint/revoke. A boot-validated service identity is the one explicit exception to the per-call SSO-verification rule (rule 2): its identity is fixed in YAML at boot, so the audit row attributes the dispatch to `service:<name>` with no fresh IdP round-trip. Upstream headers (`x-dbmcp-run-id`, `x-dbmcp-on-behalf-of`) are claimed and stored for attribution only — never authz. The exception preserves four properties — the audit contract (synchronous write, `service:<name>` identity, `user_email` synthesized), the YAML-only configuration contract (no in-band grant edits), the single non-admin permissions group, and the no-in-band-mint/revoke rule. Any future service-auth mechanism must carry the same four and land with a spec update; spec 14 and the auth/audit tests enforce them. |
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
