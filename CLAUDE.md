# CLAUDE.md

Guidance for Claude Code working in this repo.

## What this is

Self-hosted MCP gateway that brokers credentialled, audited, read-only database access for AI agents. One install per organization. Devs add the gateway URL to their MCP client; the gateway holds every DB credential, enforces SSO-driven permissions, and writes an append-only audit log on every call.

Authoritative spec lives in `docs/initial-idea/`. If you're implementing or modifying anything that touches behavior, the spec is the source of truth — match it, or update it in the same PR.

## Non-negotiables

1. **Credentials never leave the gateway.** Not in responses, not in logs, not in errors, not in admin endpoints. Never.
2. **Identity is end-to-end.** Every DB call traces to an SSO-verified user (or a named service identity), and that identity lands in the audit log.
3. **Read-only by default.** Writes require explicit per-grant opt-in *and* a target-DB role that has write privileges. The gateway will not provision write grants for you.
4. **Audit is synchronous.** If the audit write fails, the request fails. There is no best-effort audit.
5. **Config-as-code.** Permissions live in YAML reviewed by PR. No in-band admin UI. Don't add one.

## Tech stack

- **Language**: Rust (stable, pinned via `rust-toolchain.toml`)
- **Runtime**: tokio
- **HTTP**: axum
- **DB driver**: sqlx (compile-time checked, postgres-first)
- **MCP**: starts with hand-rolled JSON-RPC over HTTP+SSE; switch to a published SDK when one stabilizes
- **Config**: serde + YAML, validated at boot
- **State store**: Postgres (gateway's own, co-deployed)
- **Distribution**: OCI image on GitHub Container Registry (`ghcr.io/developerz-ai/db-mcp-gateway`), built and pushed by `.github/workflows/release.yml` on every `v*` tag

Dependencies pinned to latest stable at time of implementation. No old crates for sentimental reasons.

## Layers

One reason to change per layer. Don't blur them.

| Layer | Owns | Module |
|---|---|---|
| Transport | MCP framing over HTTP+SSE, JSON-RPC | `src/transport/` |
| Auth | OIDC flow, JWT verification, session cache | `src/auth/` |
| Authz | (user, groups, server, db, action) → allow + constraints | `src/authz/` |
| Tools | MCP tool dispatch (`list_*`, `describe_*`, `run_query`, …) | `src/tools/` |
| Query exec | Per-DB pool, statement timeout, row cap, cancellation | `src/exec/` |
| Audit | Append-only writes, retention, archive, sinks | `src/audit/` |
| Config | Parse + validate YAML, secrets resolution, hot reload | `src/config/` |
| State DB | Sessions, audit log, denylist | `src/state/` |

Files: keep them under 300 LOC. Extract by responsibility, not by line count.

## Conventions

- **Errors are typed.** Use `thiserror` for domain errors, `anyhow` only in `main.rs` boundaries. Every error returned to the client has a stable code (see `docs/initial-idea/03-mcp-tools.md`).
- **No `unwrap` / `expect` outside `main` and tests.** A panic in the hot path crashes the gateway, which crashes everyone using it.
- **Tracing, not println.** `tracing` spans on every tool dispatch with `request_id`, `user`, `server`, `database`.
- **Audit before result.** The audit write completes before the success response goes out. Use a transaction or 2-phase commit pattern with the state DB.
- **Per-DB pools, sized by config.** Never one global pool. Never share a pool across `(server, database)`.
- **No backwards-compat shims** for unreleased code. Once we cut v1, then we worry about migrations.
- **No comments restating code.** Only document non-obvious *why*: a hidden invariant, a workaround for a specific bug, behavior that would surprise a reader.

## Testing

- **Unit tests** for pure logic (authz evaluation, config validation, SQL rewriting). No real DB.
- **Integration tests** boot the gateway against a real Postgres in a container, run real MCP requests over HTTP. The CI runner has `postgres:16` as a service.
- **Property tests** for authz: given any (groups × grants), the merge always picks the most restrictive constraint. `proptest`.
- **No mocking the target DB.** If a test asserts behavior of the query path, it runs real SQL against a real Postgres.
- **Audit log assertions** in every integration test that hits a tool. If a tool ran, an audit row exists; if a tool failed authz, an audit row exists with `outcome: forbidden`.

## CI

GitHub Actions on Blacksmith runners — `blacksmith-2vcpu-ubuntu-2404` is the default for everything that doesn't need more. Postgres comes up as a service. Workflows live in `.github/workflows/`.

## Security review required for

- Any change to `src/auth/` or `src/authz/`.
- Any change to credential storage / loading.
- Any change to the audit log write path.
- Any new MCP tool.
- Any change to the SQL execution path (timeouts, row caps).

These are the parts that, if wrong, lose the entire value proposition. Reviewers should specifically look for: credentials leaking into errors/logs, missing audit rows, authz bypass via constraint-merge edge cases, and SQL injection / timeout bypass.

## What lives where

```
src/
  main.rs           # binary entrypoint, signal handling, graceful shutdown
  config/           # YAML schema, validation, secrets resolution, hot reload
  transport/        # MCP over HTTP+SSE
  auth/             # OIDC, JWT, session cache
  authz/            # grant evaluation, constraint merge
  tools/            # MCP tool implementations
  exec/             # per-DB pools, query execution, timeout, row cap
  audit/            # append-only writer, retention pruner, archive exporter, sinks
  state/            # state DB queries, migrations
  errors.rs         # typed error enum, code mapping
config/
  example.yaml      # commented example
docs/
  initial-idea/     # canonical spec — keep in sync with behavior
  usage/            # end-user (developer) docs
  deployment/       # operator docs
```

## Never

- Return a connection string, password, or role secret in any tool response, error, or log.
- Add an admin web UI for permissions. Permissions live in YAML in git.
- Mock the target DB in integration tests covering query behavior.
- Skip the audit write to make a slow path faster.
- Add a "service account / API key" auth path without a permissions group + audit identity.
- Promote a request from one user's session to another.
- Run gateway-side as a DB superuser. Read-only roles per database, full stop.
- Force-push to `main`.
- `--no-verify` on commits when hooks fail — fix the hook.

## Project context (not in code)

- Single-tenant by design. Two organizations sharing one install is unsupported.
- Distribution is Docker Hub. Helm chart is roadmap, not now.
- We are *not* building: a BI tool, a query builder, a credential vault, a SaaS, an LLM, an agent runtime.

## Docs

- `docs/initial-idea/` is the spec. Numbered files; read them in order. `00-seed.md` is the original framing for context.
- `docs/usage/` is end-user (developer) facing. Treat additions there like you'd treat a public API change.
- `docs/deployment/` is operator-facing.
- Long-form architecture decisions land here as you make them. Don't bury them in code comments.
