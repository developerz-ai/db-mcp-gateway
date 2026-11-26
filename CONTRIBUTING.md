# Contributing to db-mcp-gateway

Thanks for considering a contribution! This project is maintained by Developerz AI. We welcome bug reports, feature requests, and PRs from the community.

---

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it. Report violations to security@developerz.ai.

---

## Getting Started

### Prerequisites

Host prerequisites — `bin/setup` checks these before it installs anything:

- **Bash** and Git. On a Debian/Ubuntu host `bin/setup` installs `build-essential`, `openssl` and `curl` when missing (needs root or non-interactive `sudo`, or have an administrator install them first). On any other host it only checks that `cc`, `make`, `openssl` and `curl` are on `PATH` — install them with your package manager.
- **Rust**, including Cargo and rustc, with the pinned toolchain and the `rustfmt` and `clippy` components from `rust-toolchain.toml`. Install through your trusted toolchain manager before setup; setup does not bootstrap Rust.
- **Docker Engine or Docker Desktop** with **Docker Compose v2** (`docker compose`), including support for `up --wait`. Start the daemon and ensure your user can access it without sudo before setup; setup does not install Docker.
- **Network access** to host package repositories, Rust dependency registries and container image registries; available local ports listed below.
- **cargo-nextest** and **cargo-audit** — `bin/setup` installs CI's pinned versions as prebuilt binaries (`cargo binstall` when present, else nextest's release tarball; `cargo install` as the last resort). `bin/test` falls back to `cargo test` without nextest.
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
./bin/setup --hooks       # tools, deps, dev stack; --hooks enables .githooks/
./bin/run                 # the gateway from source on http://127.0.0.1:8443/mcp
# second terminal:
./bin/seed                # demo `shop` database on the dev target
./bin/mcp-call run_query '{"server":"local","database":"shop","sql":"select * from orders"}'
```

`bin/setup` checks Cargo and Docker before installing missing host packages and tools, fetches Rust dependencies with `cargo fetch --locked`, and starts all eight dependency services, waiting for health. Tool output goes to `target/setup.log`; a failed stage prints its message and the log's last 20 lines. The log stays local — it can hold environment values, so never paste it publicly. Without `--hooks` it leaves your git config alone and prints how to opt in.

Just want to try the gateway, no Rust toolchain? `cd examples/demo && docker compose up -d --wait` runs the published image with a seeded database and a dev-only service token, then `docker compose run --rm ready` prints the `claude mcp add` line.

`bin/dev` defaults to `up`. Running it after setup is safe: it ensures the same dependency services are up, not a second stack. This spins up:
- State PostgreSQL (gateway metadata, sessions, audit log): `localhost:5433`
- Target PostgreSQL (testing gateway queries): `localhost:5434`
- Scratch PostgreSQL (observe or set up pooler tests): `127.0.0.1:5436`
- Transaction-mode PgBouncer (uses scratch PostgreSQL): `127.0.0.1:6432`
- Target MongoDB: `localhost:27018`
- MySQL permissions store: `localhost:3307`
- Target Redis (`kind: redis`): `localhost:6380`
- Target Dragonfly (`kind: redis`): `localhost:6381`

Run `bin/test --test it_db aborted_pooled_text_casts_leave_the_backend_reusable`
to exercise client disconnects before and during text-cast execution and then
check that the same backend still serves reads. The scratch ports are fixed;
the pooler does not use the ordinary target database.

YugabyteDB is **not** in the default stack (it boots in ~21 s and takes ~0.5–0.9 GiB RAM). It sits behind the compose profile `yugabyte`: `bin/test-yugabyte` starts it with the state DB, YSQL on `localhost:5435` (`TARGET_YB_PORT`).

**Run the gateway:** `bin/run` starts `state-db` and `target-db` if they are not running, mints a dev service token once into `target/dev/service-token`, and runs `cargo run` with the committed [`config/dev.yaml`](config/dev.yaml) — dev-only defaults for `STATE_DB_URL`, `TLS_DISABLED`, `OIDC_*` and the signing-key waiver, overridden by `.env` and then by your shell. Extra flags go to `cargo run` (`bin/run --release`). A root `config.yml` (the quickstart's) is gitignored.

**Call a tool:** `bin/mcp-call <tool> [json-arguments]` POSTs one `tools/call` as that service token (`bin/mcp-call --list` for `tools/list`); `MCP_URL` and `DBMCP_TOKEN` point it at another gateway, such as the demo. It exits 1 on a JSON-RPC error or an `isError` result.

**SSO path:** `bin/run --idp` also starts Dex (compose profile `idp`, [`config/dex.yaml`](config/dex.yaml)) at `http://localhost:5556`, the `OIDC_ISSUER` in `.env.example`. Sign in as `dev@example.com` / `dev-only-password` (group `devs`). The demo's `sso` profile uses the same port, so run one at a time.

**Shared box:** `bin/test`, `bin/test-yugabyte`, `bin/lint` (clippy) and `bin/check` queue behind each other on this checkout (`flock` on `.git/dbmcp-heavy.lock`; suites that touch the dev databases also take `.git/dbmcp-db.lock` — in git's dir, so `cargo clean` never unlinks a held lock). A waiting run prints `queued: waiting for <pid: command> (lock <path>)`. Full-suite runs go through the machine-wide `heavy` ledger when it is on `PATH`. Run DB-backed suites through these wrappers, never raw `cargo test`, so two suites never share the dev databases at once. `DBMCP_NO_QUEUE=1` opts out.

**`.env` vs your shell:** every `bin/` script loads `.env` but only fills in variables your shell has not exported, so `TARGET_DB_PORT=5444 bin/test` wins over the file.

`bin/check` first checks required tools and Docker daemon access, then runs `bin/ci` unchanged (format checks, Clippy, integration tests, the SHA-pin and secret-scan parity stages, plus cargo-audit when installed). Exit `75` means a required preflight resource is unavailable and the gate did not run; repair the named prerequisite and retry. Once CI starts, its exit status is preserved: lint, compilation and test failures are not reclassified as infrastructure failures. Exit `0` means the gate passed.

**Check logs:** `bin/dev logs`  
**Tear down:** `bin/dev down`  
**psql into state DB:** `bin/dev psql state`  
**psql into target DB:** `bin/dev psql target`  
**ysqlsh into target YugabyteDB:** `bin/dev ysqlsh` (start it first with `bin/test-yugabyte`)  

### Inner loop

**Git hooks** (opt in: `bin/setup --hooks`, or `git config core.hooksPath .githooks`):

| Hook | Runs | Budget |
|---|---|---|
| `pre-commit` | `cargo fmt --check`, a service-token scan of the staged diff (CI's regex and exempt paths), shellcheck on staged scripts when installed | seconds |
| `pre-push` | `cargo clippy --all-targets --all-features -D warnings`, `bin/test --unit` | minutes |

The full gate — integration tests against the dev stack, audit, docs — is `bin/check`, run on demand; CI runs the same jobs on every PR. Fix a failing hook rather than skipping it.

**bacon** (`cargo install --locked bacon`): `bacon` re-runs clippy on save; `bacon unit` the Docker-free tests, `bacon test` the full suite (dev stack up), `bacon run` the gateway via `bin/run`. Jobs live in [`bacon.toml`](bacon.toml).

**mold (optional, Linux).** Linking dominates incremental rebuilds of the test binaries. With [mold](https://github.com/rui314/mold) and clang installed, add to your **user** config `~/.cargo/config.toml` — not the repo's `.cargo/config.toml`, which CI and the Docker build share:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

(`aarch64-unknown-linux-gnu` for arm64.) Remove the block if a link fails; nothing in the repo depends on it.

**Dev container.** [`.devcontainer/`](.devcontainer/) merges a Rust workspace container over `docker-compose.dev.yml` and starts it with the eight default services, under the same compose project `bin/dev up` uses — opening it joins a running stack instead of starting a second one. The workspace shares the host network, so `.env`, the tests and the `localhost` ports work unchanged (Linux, or Docker Desktop with host networking enabled). It has no Docker CLI: run `bin/test --unit`, `cargo nextest run …` and `cargo run -- --config config/dev.yaml` inside; `bin/dev`, `bin/test`, `bin/seed` and `bin/run` drive Docker and stay on the host.

### Project Structure

See [CLAUDE.md](CLAUDE.md) and its scoped files:
- [src/CLAUDE.md](src/CLAUDE.md) — **layers** and **conventions** (error handling, async patterns, logging, code style)
- [tests/CLAUDE.md](tests/CLAUDE.md) — **testing** rules
- [bin/CLAUDE.md](bin/CLAUDE.md) — **commands** beyond the essentials in the root file

---

## Making Changes

### 1. Code Style

We follow Rust idioms, enforced by:

```bash
bin/fmt             # Format with rustfmt (max_width=100)
bin/fmt --changed   # Only the .rs files changed vs origin/main, plus untracked ones
bin/lint            # Check fmt + clippy -D warnings (CI's two clippy passes)
bin/lint --lib      # Fast loop: fmt check + one clippy pass over lib + bins
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

See [src/CLAUDE.md](src/CLAUDE.md#conventions) for full conventions.

### 2. Testing

**Run all tests:**
```bash
bin/test    # All targets + all features, including bench-harness tests; starts dev stack
```

**Run the unit loop (no Docker):**
```bash
bin/test --unit    # --lib --bins + tests/it_offline; what the pre-push hook runs
```

Before invoking cargo, `bin/test` always runs the idempotent
`docker compose -f docker-compose.dev.yml up -d --wait`, waiting for all eight
services to become healthy even when the state DB is already running. A stack
that never became healthy returns **75** without running cargo, and the report
names every unhealthy service with its state and health. **75** is reserved for
an unreachable resource or a confirmed health failure: a malformed compose file
or any other compose command failure keeps its own exit status, so a broken
compose file is blamed on the change and not on the box. Test arguments pass
through; several name filters work without `--` (`bin/test --test it_db a:: b::`
— under plain `cargo test` they are moved behind `--`).

**Run the suite against YugabyteDB:**
```bash
bin/test-yugabyte    # Postgres query-path suite against YugabyteDB (YSQL); needs cargo-nextest
```

It starts the state DB and `target-yugabyte` (compose profile `yugabyte`), waits for health, and runs nextest's `yugabyte` profile — `.config/nextest.toml` holds the suite filter and each YugabyteDB exclusion. The tests read `TARGET_DB_PORT` and `TARGET_FLAVOR=yugabyte`. CI runs the same suite as the `yugabyte` job. Plain `bin/test` never touches YugabyteDB.

**Run a single test:**
```bash
bin/test --test <name>      # Integration test by file name
cargo test <pattern>         # Unit test by pattern
```

**Check your files while the tree is mid-edit** (several people or agents in one checkout):
```bash
bin/snapshot-check src/foo.rs tests/it_offline/foo.rs              # clippy + unit tests on HEAD + these files
bin/snapshot-check src/foo.rs -- cargo test --test it_offline foo   # any command instead
```
It exports `HEAD` into `target/snapshot/<slot>/tree`, copies only the listed files over it and runs with its own `CARGO_TARGET_DIR`, so someone else's half-done edit cannot break your check. `--slot NAME` runs beside another snapshot; DB suites stay on `bin/test`.

**Serial tests:** a test in `tests/it_db/` marked `#[serial_test::serial(world)]` must also run alone under nextest. `bin/regen-serial` rewrites that list in `.config/nextest.toml` (`--check` only reports); `it_offline::isolation_guard` fails until it is current.

**Deploy manifests:** `bin/check-deploy` runs promtool, `helm lint` and kubeconform on `deploy/` through pinned images (Docker only) — CI's `deploy` job.

**Test coverage:**
- **Unit tests** — pure logic (authz eval, config validation, SQL rewriting). No real DB. Inline at the bottom of each source file.
- **Property tests** — authz constraint-merge logic in `*_proptests.rs` files (e.g., `src/authz/effective_proptests.rs`). Uses `proptest` crate.
- **Integration tests** — `tests/it_db/*.rs` (+ `tests/it_offline/`, `tests/it_global/`) files against real Postgres instances. **NEVER mock the target DB** in query-path tests.

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
| `ci.yml` / `test` | `bin/test`: `cargo nextest run --all-targets --all-features` when cargo-nextest is installed, else `cargo test` with the same flags, including bench-harness tests, real-DB setup and argument forwarding |
| `ci.yml` / `audit` | `cargo audit` — CI's exact command; no advisory is ignored, on the command line or in `.cargo/audit.toml` (the one config cargo-audit reads) |
| `ci.yml` / `secret-scan` | `bin/secret-scan`, the script the workflow (and `.githooks/pre-commit`, with `--staged`) runs: every tracked file's contents, file names and symlink targets, fail-closed (exit 2) when the scan cannot run, reporting a hit by location (`path:line` or a masked path) and never by the matched credential — plus the regex regression run from the same script CI runs (`bash tests/bin/secret-scan-regex.test.sh`) |
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
- **Gate-scoped** — a toolchain that belongs to exactly one job: python3 (the
  public-tree guard), cargo-audit (the audit job) and Node 20+/npm plus the installed website dependencies (the
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

`bin/setup` prepares native/Rust dependencies, installs cargo-nextest and
cargo-audit, and starts the eight default Compose services; it does **not**
install website dependencies. Run `cd website && npm ci` to have every job run.

The gate mirrors ci.yml's SHA-pin validation and secret-scan: a local gate
that skipped them would let unpinned actions and committed service tokens pass
before the push. The token scanner and the regex regression are single copies
shared with the workflow (`bin/secret-scan`, `tests/bin/secret-scan-regex.test.sh`;
`tests/bin/secret-scan.test.sh` pins the scanner against a real index); the
SHA-pin grep is a port of the workflow's step, and `tests/bin/check.test.sh`
exercises both stages' verdicts (a pinned ref passes, a mutable tag fails, an
unreadable workflows directory fails closed; a token hit and a scanner that
cannot run both fail the gate), so drift between the
workflow and the gate turns red instead of passing silently.
What the local gate adds beyond `bin/lint` (fmt, both clippy configurations and
the scrub-feature guard) is the all-target/all-feature test invocation through
`bin/test`, CI's exact audit command `cargo audit` (no ignores),
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
- **Security-review paths get a mandatory security pass.** A PR touching auth, authz, credential
  loading, the audit write path, MCP tools, SQL execution or the state DB carries the
  `security review required` label; the agent merges it only once that pass has nothing open.
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
- Whether a release is due is decided weekly by the maintainer agent (`.dz/schedules/release-due.md`); a published tag is never moved or deleted.

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
