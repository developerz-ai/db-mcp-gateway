# Contributing to db-mcp-gateway

Thanks for considering a contribution! This project is maintained by Developerz AI. We welcome bug reports, feature requests, and PRs from the community.

---

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it. Report violations to security@developerz.ai.

---

## Getting Started

### Prerequisites

Host prerequisites — `bin/setup` checks these before it installs anything:

- **Debian/Ubuntu host** for `bin/setup`, with Bash, `dpkg` and `apt-get`. Install Git to clone the repo. If packages are missing, setup needs root or non-interactive `sudo`; alternatively, have an administrator install `build-essential`, `openssl` and `curl` first.
- **Rust**, including Cargo and rustc, with the pinned toolchain and the `rustfmt` and `clippy` components from `rust-toolchain.toml`. Install through your trusted toolchain manager before setup; setup does not bootstrap Rust.
- **Docker Engine or Docker Desktop** with **Docker Compose v2** (`docker compose`), including support for `up --wait`. Start the daemon and ensure your user can access it without sudo before setup; setup does not install Docker.
- **Network access** to host package repositories, Rust dependency registries and container image registries; available local ports listed below.
- **cargo-nextest** (`bin/setup` installs the pinned version) — `bin/test` falls back to `cargo test` without it.
- **mise** is optional: setup runs `mise install` when available and otherwise uses host tools. A failed mise install stops setup.

`bin/check` grades the same box, and a missing REQUIRED prerequisite returns
**75** because the gate cannot grade anything at all:

- **Rust** stable (pinned in `rust-toolchain.toml`), with rustfmt and clippy
- **Docker** and **Docker Compose** (for local dev stack), with a reachable daemon
- **Bash** and **GNU grep**, a C compiler (`cc`), and `make`

Gate-scoped — each toolchain belongs to exactly one job, so an absent one is
reported `NOT RUN` and every other job is still graded:

- **cargo-audit** on `PATH` (audit job) — `cargo install cargo-audit`
- **Node.js 20+** and **npm** (Pages job) — `install: Node 20+ and npm`
- **Website dependencies** (Pages job) — `cd website && npm ci`

**PostgreSQL** client tools (psql) are for `bin/dev psql` against the dev stack;
the helpers run psql inside the containers, so a host PostgreSQL client is optional.

### Local Development

From a fresh checkout with the host prerequisites installed:

```bash
git clone https://github.com/developerz-ai/db-mcp-gateway.git
cd db-mcp-gateway
cp .env.example .env
./bin/setup
./bin/dev
./bin/check
```

`bin/setup` checks Cargo and Docker before installing missing host packages, fetches Rust dependencies with `cargo fetch --locked`, and starts all four dependency services, waiting for health. Failures stop at the named stage with an actionable diagnostic; subprocess output is suppressed to avoid exposing environment values. Review any detailed diagnostics locally, and never share credentials.

`bin/dev` defaults to `up`. Running it after setup is safe: it ensures the same dependency services are up, not a second stack. This spins up:
- State PostgreSQL (gateway metadata, sessions, audit log): `localhost:5433`
- Target PostgreSQL (testing gateway queries): `localhost:5434`
- Target MongoDB: `localhost:27018`
- MySQL permissions store: `localhost:3307`

**Neither setup nor bin/dev starts the gateway.** Follow the [deployment quickstart's local walkthrough](website/docs/deployment/quickstart.md#run-it-locally) for separate gateway startup and the unauthenticated MCP smoke request, which should return HTTP `401`.

`bin/check` first checks required tools and Docker daemon access, then runs `bin/ci` unchanged (format checks, Clippy, integration tests, the SHA-pin and secret-scan parity stages, plus cargo-audit when installed). Exit `75` means a required preflight resource is unavailable and the gate did not run; repair the named prerequisite and retry. Once CI starts, its exit status is preserved: lint, compilation and test failures are not reclassified as infrastructure failures. Exit `0` means the gate passed.

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
bin/test    # All targets + all features, including bench-harness tests; starts dev stack
```

Before invoking cargo, `bin/test` always runs the idempotent
`docker compose -f docker-compose.dev.yml up -d --wait`, waiting for all four
services to become healthy even when the state DB is already running. A stack
that never became healthy returns **75** without running cargo, and the report
names every unhealthy service with its state and health. **75** is reserved for
an unreachable resource or a confirmed health failure: a malformed compose file
or any other compose command failure keeps its own exit status, so a broken
compose file is blamed on the change and not on the box. Test arguments pass
through unchanged.

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
- Update the spec in `website/docs/initial-idea/` in the **same PR**.
- Examples: new MCP tool, new authz constraint, new config field.

### 4. Security Sensitive Changes

Changes to the following **must have a `security review required` label** on the PR:

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

1. **Run local quality gates** (see [gate matrix](#local-quality-gate-matrix)):
   ```bash
   bin/check    # Delegates to bin/ci; validation only, never publishes
   ```

2. **Commit with a clear message:**
   ```bash
   git commit -m "Brief one-line title

   - What changed
   - Why it was needed

   Co-Authored-By: Your Name <your.email@example.com>"
   ```

3. **If you touched security-sensitive code:** add the `security review required` label yourself (or request a reviewer to do so).

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

### Local quality gate matrix

`bin/check` delegates to `bin/ci`. GitHub Actions independently configures the
quality jobs in [ci.yml](.github/workflows/ci.yml) and validation in
[pages.yml](.github/workflows/pages.yml); CI does **not** call `bin/check`.

| Workflow job / validation | Local gate |
|---|---|
| `ci.yml` / `fmt` | `bin/lint`: `cargo fmt --all -- --check`, then the job's SHA-pin scan — same anchoring, 40-hex allow regex and local-action exemption as the workflow's step; each grep's status is checked on its own, so a scan that cannot read `.github/workflows` fails closed instead of reporting an empty result |
| `ci.yml` / `clippy` | `bin/lint`: debug all-target/all-feature clippy and release all-feature clippy, both `-D warnings`; `bin/check-scrub-features` checks the non-dev regex feature graph |
| `ci.yml` / `test` | `bin/test`: `cargo test --all-targets --all-features`, including bench-harness tests, real-DB setup and argument forwarding |
| `ci.yml` / `audit` | `cargo audit --ignore RUSTSEC-2023-0071` — CI's exact command; the ignore set is unchanged (only `RUSTSEC-2023-0071`, justified in `.cargo/audit.toml` and `audit.toml`) |
| `ci.yml` / `secret-scan` | The tracked-token scan — same `git grep` regex and pathspec exclusions as the workflow, fail-closed on any non-1 grep status, reporting a hit by location (`path:line`) and never by the matched credential — plus the regex regression run from the same script CI runs (`bash tests/bin/secret-scan-regex.test.sh`) |
| `pages.yml` / `build` | In `website/`: `npm run typecheck` and `npm run build` |
| `pages.yml` / pre-upload artifact guard | Post-build sensitive/config-asset denylist over `website/build/` |
| Local orchestration regression | `bash tests/bin/check.test.sh`: temporary fixture checkouts and command stubs, no real DB mocks or recursive full-gate execution |

The gate installs nothing. It separates two kinds of missing prerequisite:

- **Required** — cargo/rustc/rustfmt/clippy, a C compiler (`cc`), `make`, GNU
  grep, the Docker CLI, the Docker daemon, Docker Compose, and a dev stack that
  never became healthy. A missing one returns **75**: the gate
  cannot grade anything, so it refuses to grade rather than reporting a verdict.
  The refusal lives in exactly one place — `bin/check`'s preflight; no gate job
  repeats it.
- **Gate-scoped** — a toolchain that belongs to exactly one job: cargo-audit
  (the audit job) and Node 20+/npm plus the installed website dependencies (the
  Pages job). A missing one makes that one job report
  `NOT RUN: <job> - <reason> (<how to enable it>)`; the gate keeps grading every
  other job and still reaches a verdict.

A job that runs and fails keeps its own non-zero exit code — a red gate is
never converted into a skip. Every job that did not run is named in the output
and repeated in the final summary; the summary then reads
`✓ Local quality checks passed for the gates that ran (no publishing or deployment)`
rather than claiming a full pass. A gate that stops early names the jobs it
never reached the same way — each gets a `NOT RUN: <job> - <reason>` notice and
an entry in the final list — so a stopped gate never hides the work that did
not run.

`bin/setup` prepares native/Rust dependencies and starts the four Compose
services; it does **not** install cargo-audit or website dependencies. Prepare
those separately to have every job run.

The gate mirrors ci.yml's SHA-pin validation and secret-scan: a local gate
that skipped them would let unpinned actions and committed service tokens pass
before the push. The regex regression is a single copy shared with the
workflow (both run `tests/bin/secret-scan-regex.test.sh`); the two greps are
ports of the workflow's steps, and `tests/bin/check.test.sh` pins the
tracked-token scan's exact command line (git is stubbed in its fixture) and
exercises both scans' verdicts (a pinned ref passes, a mutable tag fails, an
unreadable workflows directory fails closed; a token match is reported by
location only and a grep failure fails closed), so drift between the
workflow and the gate turns red instead of passing silently.
What the local gate adds beyond `bin/lint` (fmt, both clippy configurations and
the scrub-feature guard) is the all-target/all-feature test invocation through
`bin/test`, CI's exact audit command `cargo audit --ignore RUSTSEC-2023-0071`
instead of a bare `cargo audit` that leaned on cargo-audit's config discovery,
the Pages-parity job and the orchestration regression. There is no separate
Rust typecheck job: clippy supplies that check; the separate typecheck is the
website's.

Local website validation runs whenever the site toolchain is present, and the
Pages job is reported `NOT RUN` when it is absent; Pages keeps its existing path
filters. Local checks deliberately exclude CI cache cleanup, registry login,
image builds/pushes, manifest pushes, release publication, Pages artifact upload
and deployment. Those credentialed publishing steps remain CI-only. Local success
is evidence of validation, not a guarantee of deployment success.

---

## How this project is maintained

db-mcp-gateway is AI-maintained. The [developerz.ai](https://developerz.ai) maintainer agent
triages issues, reviews and merges pull requests, and lands dependency updates; every comment it
posts is marked as coming from a bot. Its policy is [`.dz/maintainer/maintainer.yml`](.dz/maintainer/maintainer.yml).
What that means for you:

- **Issues.** A bug report needs steps, expected, actual and version (the issue form asks for
  them). If the agent asks for one of them and hears nothing, it reminds you at 7 days and closes
  the issue at 14. Answer on the closed issue and it reopens. Issues quiet for 30 days are swept:
  the agent comments before closing, never closes first. Reply to keep your issue open.
- **Pull requests.** A PR merges when the required checks are green and the review has nothing
  left open. The `main-protection` ruleset is the single authority for which checks a merge
  requires; read the live list with `gh api repos/developerz-ai/db-mcp-gateway/rulesets` rather
  than trusting a copy in the docs. When the next move is yours (a red required check, an open
  review thread, a conflict), the agent pings at 7 and 14 days and closes the PR at 21 (28 for a
  draft). Push or reply and it picks the PR back up.
- **Commit with an email linked to your GitHub account** (`git config user.email` matches an
  address on <https://github.com/settings/emails>). The ruleset requires an extra human approval
  for a commit not attributed to a GitHub account, so such a PR silently parks instead of merging.
- **A human merges security-review paths.** A PR touching auth, authz, credential loading, the
  audit write path, MCP tools, SQL execution or the state DB carries the `security review required`
  label and is merged by a person after that review, never by the bot.
- **A "no" comes early and with a reason.** A change the project will not take (the
  Non-negotiables and NEVER list in [`CLAUDE.md`](CLAUDE.md), the `non_goals` in the policy file)
  is closed with the rule it ran into, not left open.
- **A human is asked** for security reports, license questions and breaking changes (tool
  surface, error codes, config schema, audit shape). Report a vulnerability privately as
  [SECURITY.md](SECURITY.md) describes, not in an issue.

New features are still designed and built by the team, humans and AI together. Open an issue
before a large feature PR so the direction is agreed first.

---

## Release Process

Cutting a release is documented in [`website/docs/deployment/releasing.md`](website/docs/deployment/releasing.md). TL;DR:
- A `chore(release): X.Y.Z` PR bumps `version` in `Cargo.toml` (plus `Cargo.lock` and `README.md`) and nothing else.
- After it merges, an annotated `vX.Y.Z` tag on the merge commit runs `release.yml`, which builds and pushes the image to GHCR (`ghcr.io/developerz-ai/db-mcp-gateway:X.Y.Z`) and cuts the GitHub Release.
- There is no `CHANGELOG.md`: the GitHub Release's notes are generated from the merged PR titles, so a PR title says what changed for someone running the gateway.
- Whether a release is due is decided weekly by the maintainer agent (`.dz/briefs/release-due.md`); a published tag is never moved or deleted.

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
