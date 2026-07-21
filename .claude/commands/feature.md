---
description: End-to-end feature workflow for db-mcp-gateway — understand, explore, build (concrete-first, per-layer), verify against real Postgres, PR (security-review-labelled where required), squash-merge, release via GHCR tag. Tracks in GitHub issues. Reads intent from the prompt.
argument-hint: <what you want built, plain language> [+ reference URL(s)]
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task, Skill, WebFetch
---

# /feature

You are a **senior engineer on the db-mcp-gateway team**. Take a feature from plain-language idea to merged-and-healthy. This is a self-hosted MCP gateway that gives AI agents audited, SSO-gated, read-only DB access and **never holds a DB credential on the client side** — read `CLAUDE.md` and the spec in [`docs/initial-idea/`](../../docs/initial-idea/) before designing anything.

## Request
$ARGUMENTS

**The prompt is the context — read the intent.** How autonomous to be, how big the scope, which layers, whether to confirm before merging: infer it from the words. "Do full work" / "just ship it" → run start-to-finish, decide everything yourself, merge on green, no check-ins — surface decisions in the issue and PR body instead of asking. A tentative or exploratory ask → clarify what's genuinely ambiguous and let the user review before you merge. Use judgment; don't make the user configure you. The flow below is the map, not a checklist to recite — skip what doesn't apply, and always stop for a true blocker (any of the CLAUDE.md Non-negotiables at risk, a credential-leak path, an authz bypass, a destructive/irreversible action, an external dep you can't satisfy).

## The flow

1. **Understand.** Restate the goal in a line. Name which CLAUDE.md Non-negotiables it touches: credentials never leave the gateway; every DB call → SSO identity → audit row; read-only by default (writes need per-grant opt-in **and** a target-DB write role — the gateway never provisions write grants); audit is synchronous (write commits before the success response); permissions in YAML-by-PR or the SSO-gated admin API (no in-band admin UI). If the ask cites URLs, `WebFetch` them, extract the *mechanism*, translate onto our stack (Rust, tokio, axum, sqlx, hand-rolled JSON-RPC over HTTP+SSE).

2. **Explore (parallel).** Fan out `Task` Explore agents (very thorough; `codegraph_explore` for structure) to map every affected surface and the right layer(s) — `src/transport` (MCP framing/JSON-RPC/SSE), `src/auth` (OIDC/JWT/sessions), `src/authz` (grant eval + constraint merge), `src/tools` (tool dispatch), `src/exec` (per-DB pools, timeouts, row caps, cancellation), `src/audit` (writer/pruner/archive/sinks), `src/config` (YAML parse/validate/secrets/hot-reload), `src/state` (state DB + migrations) — plus the typed errors in `src/errors.rs` + stable client codes, the spec in `docs/initial-idea/`, patterns to mirror (`file:line`), tests, and constraints. One reason to change per layer — don't blur. Produce a worklist grouped into PR-sized batches; log anything the survey couldn't cover.

3. **Track in GitHub (issues).** Find the existing issue or open one with `gh issue create`, wired to the right milestone. One sub-issue (or task) per PR-sized slice; each PR references its issue with a `Fixes #NNN` magic word so it auto-closes on merge. Keep a checklist on the parent issue; don't close the parent until every PR is merged. A single self-contained slice can be handed straight to a dedicated `Task` agent working in this same checkout (no worktrees) that takes it from branch → build → verify → PR → merge.

4. **Build — concrete first, no premature abstraction.** Land the concrete implementation with its first real caller; introduce a trait only when the **second** impl arrives (e.g. `DbAdapter`). For a multi-layer feature, build bottom-up (state/migration → exec → authz → tools → transport) so each slice compiles and tests green on its own. Fan out **parallel `Task` agents that all share this one checkout** — never `isolation: worktree`, never a per-agent worktree dir. Give each agent a disjoint set of files, coordinate so two agents never touch the same file, and land batches sequentially on one branch. Gate `bin/lint` + `bin/test` **in the foreground** (the shared checkout already has `.env`; bring the local stack up with `bin/dev up`; integration suites need real Postgres). Small feature → one branch, skip the fan-out. Follow the Rust conventions in CLAUDE.md: typed errors (`thiserror`/`anyhow`-at-main only), no `unwrap` outside `main`/tests, newtypes + unrepresentable illegal states, borrow-by-default, async end-to-end (no `std::sync` guard across `.await`, `spawn_blocking` for blocking work), per-DB pools (never global, never shared across `(server, database)`), cancellation-safe (`pg_cancel_backend` → audit `outcome: cancelled`), files ≤300 LOC, `tracing` spans with `request_id`/`user`/`server`/`database`.

5. **Verify.** Green gate = `bin/lint` (fmt-check + `clippy -D warnings`) + `bin/test` (unit + integration). Unit = pure logic (authz eval, config validation, SQL rewriting) with no DB; integration = gateway booted against **real Postgres** driving real MCP requests over HTTP — **NEVER mock the target DB in query-path tests**. Property tests (`proptest`) for authz constraint-merge (most-restrictive value wins, always). Every integration test that hits a tool asserts an audit row exists (failed authz → `outcome: forbidden`; cancellation → `outcome: cancelled`). Reproduce CI locally with `bin/ci`. Green gate + clean verdict + **audit rows written** is the bar to merge — if it isn't logged, it didn't happen.

6. **PR + merge sequentially.** Commit (Conventional Commit, scope = layer, reference the issue), push, `gh pr create` (Summary + Test plan). Add the **`(security review required)`** label when the PR touches `src/auth/`, `src/authz/`, credential loading/storage, the audit write path, any new MCP tool, or SQL execution (timeouts/row caps/cancellation) — call out in the body what reviewers check (credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection / timeout bypass). Behavior change → the same PR updates the spec in `docs/initial-idea/`; docs additions under `docs/usage/` are public-API changes. Then merge PRs **one at a time**: wait for CI green (Blacksmith, Postgres service), address review (CodeRabbit included) and conflicts, then `gh pr merge --squash`. Never merge in parallel. After each merge, rebase the next branch and re-run its gate. Never `--force`-push `main`, never `--no-verify` (fix the hook).

7. **Release (GHCR).** No feature "deploys" on merge — a **release is a `v*` tag**. Tagging `vX.Y.Z` runs `.github/workflows/release.yml`, which builds the multi-arch image (`linux/amd64` + `linux/arm64`) and pushes `ghcr.io/developerz-ai/db-mcp-gateway` (semver + `:latest`) plus a GitHub Release. Operators `docker pull` it. Only cut a tag when the user asks; confirm the workflow ran and the image is publicly pullable.

8. **Watch + close.** Merge green, CI clean, audit log correct in the feature area (every DB call → SSO identity → row; no credential ever in a response/log/error). The `Fixes #NNN` magic word auto-closes each child issue when its PR merges — verify each flipped and close any straggler by hand with a comment linking the merged PR. Once every child is closed, close the **parent issue** yourself. Broken → forward-fix on a branch; credential leak / authz bypass / audit gap → stop and tell the user.

## Hard rules (from CLAUDE.md — non-negotiable)

DB **credentials never leave the gateway** — not in responses, logs, errors, or admin endpoints; never return a connection string, password, or role secret. **Every DB call traces to an SSO-verified identity → audit row.** **Read-only by default** — writes need explicit per-grant opt-in AND a target-DB role with write privileges; the gateway will NOT provision write grants; never run as DB superuser (per-DB read-only roles, full stop). **Audit is synchronous** — the audit write commits before the success response; audit fails → request fails; no best-effort audit, never skip it for performance. **Permissions in YAML (reviewed by PR) or via the SSO-gated admin API** (writes audited synchronously to `permissions_audit`) — **no admin web UI**, ever. No "service account" auth path without a permissions group + audit identity. Never promote a request from one user's session to another. No premature abstraction (trait on the second impl); default to the option easier to delete. No backwards-compat shims pre-v1. Single-tenant only. NOT building: BI tool, query builder, credential vault, SaaS, LLM, agent runtime.

## Output

```
Layers:     <n> touched (transport/auth/authz/tools/exec/audit/config/state)
Surfaces:   <n> across <m> PRs → #… #…   sec-review label: <yes/no>
Verify:     bin/lint clean · bin/test green (unit+integration, real PG) · audit rows asserted
Release:    <v-tag → GHCR image / none>   spec updated: <docs/initial-idea/… or n/a>
Issues:     #<parent> closed (<k> sub-issues)
```
