# Contributing to db-mcp-gateway

Thanks for considering a contribution! This project is maintained by Developerz AI. We welcome bug reports, feature requests, and PRs from the community.

---

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it. Report violations to security@developerz.ai.

---

## Getting Started

### Prerequisites

- **Rust** stable (pinned in `rust-toolchain.toml`)
- **Docker** and **Docker Compose** (for local dev stack)
- **PostgreSQL** client tools (psql)

### Local Development

Clone the repo and bring up the dev stack:

```bash
git clone https://github.com/developerz-ai/db-mcp-gateway.git
cd db-mcp-gateway
bin/dev up
```

This spins up:
- A "state DB" (gateway metadata, sessions, audit log) on `localhost:5433`
- A target PostgreSQL instance on `localhost:5434` (for testing gateway queries)

**Check logs:** `bin/dev logs`  
**Tear down:** `bin/dev down`  
**psql into state DB:** `bin/dev psql state`  
**psql into target DB:** `bin/dev psql target`  

### Project Structure

See [CLAUDE.md](CLAUDE.md) — it documents:
- **Layers** (`src/transport/`, `src/auth/`, `src/authz/`, `src/tools/`, `src/exec/`, `src/audit/`, `src/config/`, `src/state/`)
- **Conventions** (error handling, async patterns, logging, testing, code style)
- **Commands** (build, test, lint, CI)

---

## Making Changes

### 1. Code Style

We follow Rust idioms, enforced by:

```bash
bin/fmt       # Format with rustfmt (max_width=100)
bin/lint      # Check fmt + clippy -D warnings
```

Key rules:
- **No `unwrap`/`expect`** outside `main.rs` and tests — propagate with `?`, branch with `match`/`if let`/`let-else`.
- **Errors are typed** — use `thiserror` for domain errors; `anyhow` only at `main.rs`.
- **Newtypes over primitives** — `RequestId(String)`, not `String`.
- **Borrow by default** — `&str` over `String`, `&[T]` over `Vec<T>`. `.clone()` only when ownership moves.
- **Async end-to-end** — tokio only on the request path; never `std::sync::Mutex` across `.await`.
- **Comments explain the *why*, not the *what*.** Rename until code is self-documenting.
- **Per-DB pools** — never one global pool.
- **Tracing, not `println`** — use `tracing` spans with `request_id`, `user`, `server`, `database`.
- **File size:** ≤300 LOC. Split by single responsibility.

See [CLAUDE.md](CLAUDE.md#conventions) for full conventions.

### 2. Testing

**Run all tests:**
```bash
bin/test    # Unit + integration (auto-brings up dev stack)
```

**Run a single test:**
```bash
bin/test --test <name>      # Integration test by file name
cargo test <pattern>         # Unit test by pattern
```

**Test coverage:**
- **Unit tests** — pure logic (authz eval, config validation, SQL rewriting). No real DB. Inline at the bottom of each source file.
- **Property tests** — authz constraint-merge logic in `*_proptests.rs` files (e.g., `src/authz/effective_proptests.rs`). Uses `proptest` crate.
- **Integration tests** — `tests/*.rs` files against real Postgres instances. **NEVER mock the target DB** in query-path tests.

**MUST DO:** Every tool integration test asserts an audit row exists. Forbidden path → `outcome: forbidden`.

Example assertion:
```rust
assert!(audit_row_for_request(&state_db, request_id).await.exists);
```

### 3. Behavior Changes

If you change behavior:
- Update the spec in `docs/initial-idea/` in the **same PR**.
- Examples: new MCP tool, new authz constraint, new config field.

### 4. Security Sensitive Changes

Changes to the following **must have a `(security review required)` label** on the PR:

- `src/auth/`, `src/authz/`
- Credential loading or storage
- Audit write path (any changes to append-only log)
- New MCP tool
- SQL execution (timeouts, row caps, cancellation)
- Permission loading or evaluation

Reviewers check for:
- Credentials in errors/logs/responses
- Missing audit rows
- Authz bypass via constraint-merge edges
- SQL injection / timeout bypass
- Rate limiting / resource exhaustion

---

## Submitting a PR

### Before You Push

1. **Run the full CI locally:**
   ```bash
   bin/ci    # Runs fmt check, clippy, all tests
   ```

2. **Commit with a clear message:**
   ```bash
   git commit -m "Brief one-line title

   - What changed
   - Why it was needed

   Co-Authored-By: Your Name <your.email@example.com>"
   ```

3. **If you touched security-sensitive code:** add the `(security review required)` label yourself (or request a reviewer to do so).

### PR Title & Description

- **Title:** Concise, present tense. Examples: "Add row-limit constraint evaluation", "Fix SQL injection in CTE rewriting", "Improve error clarity for missing OIDC token".
- **Description:** Explain the problem and solution. Link to any related issues.

### What We Review For

- **Correctness** — Does the code do what it claims? Are all paths tested?
- **Security** — Credentials/tokens safe? Audit rows logged? Authz not bypassed?
- **Style** — Follows CLAUDE.md conventions? Borrowing correct? Errors typed?
- **Testing** — Unit + integration coverage? Real DB (not mocks)?
- **Docs** — Spec updated? Code comments explain non-obvious *why*?

---

## CI & Tooling

The repo uses GitHub Actions (Blacksmith CI runners). You can reproduce CI locally:

```bash
bin/ci      # Exactly what GitHub Actions runs
```

This runs:
- `bin/fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `bin/test` (unit + integration)

---

## Release Process

Cutting a release is documented in [`docs/deployment/releasing.md`](docs/deployment/releasing.md). TL;DR:
- Tag a commit with `v<major>.<minor>.<patch>`.
- GitHub Actions auto-builds and pushes to GHCR (`ghcr.io/developerz-ai/db-mcp-gateway:X.Y.Z`).
- Update `CHANGELOG.md` in the same PR.

---

## Getting Help

- **General questions:** Open a GitHub issue.
- **Security issues:** Email security@developerz.ai (see [SECURITY.md](SECURITY.md)).
- **Design questions:** Open an issue to discuss before coding.
- **Stuck?** Open a draft PR and ask for guidance.

---

## License

By contributing, you agree that your contributions are licensed under the same MIT license as the project. See [LICENSE](LICENSE).

---

Thanks for helping make db-mcp-gateway better! 🙌
