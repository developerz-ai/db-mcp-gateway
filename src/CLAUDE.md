# src/ — layers and code conventions

Binding for every change under `src/`, on top of the root [`CLAUDE.md`](../CLAUDE.md).

## Layers

One reason to change per layer. Don't blur.

| Layer | Owns | Module |
|---|---|---|
| Boot | entry, signals, graceful shutdown (`main.rs`); library root the integration tests drive (`lib.rs`); boot helpers (tracing, state DB, app state, serve) + background tasks | `src/main.rs`, `src/lib.rs`, `src/startup/` |
| Transport | HTTP routes, request id, budgets/timeouts, OAuth handlers, admin API; JSON-RPC envelope, MCP payloads + tool names (shared by transport and tools) | `src/transport/`, `src/mcp/` |
| Auth | OIDC, JWT, session cache, service tokens, OAuth state (`src/auth/oauth/`) | `src/auth/` |
| Authz | (user, groups, server, db, action) → allow + constraints; per-replica cache, admin commits reach other replicas via LISTEN/NOTIFY, SIGHUP reloads YAML | `src/authz/` |
| Tools | MCP tool dispatch | `src/tools/` |
| Exec | Per-DB pool, statement timeout, row cap, cancellation (`pg/`, `mongo/`, `redis/`) | `src/exec/` |
| Audit | Append-only writes, retention, archive, sinks | `src/audit/` |
| Config | YAML parse + validate + secrets resolve + hot reload | `src/config/` |
| State DB | Sessions, audit log, denylist, permissions store (`state/permissions/pg.rs`, `state/permissions/mysql/`). No central `errors.rs` — each layer owns its typed error | `src/state/` |
| Scrubbing | credential scrubbing for GlitchTip | `src/sentry_scrub/` |

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
