# Reviewer instructions — developerz-ai/db-mcp-gateway

> Read by the developerz.ai reviewer at EVERY review of this repository, at the reviewed
> commit, as this repo's own layer of the reviewer's prompt — established by dz-runner setup mode.
> It refines the platform rules (a finding is cited or withheld; the bot always discloses)
> and never overrides them. Edit freely; keep it under 12,000 characters — past that it is cut.

## Stack

Rust + Cargo. The gate is `bin/check`, run from the repository root: `export PATH="$HOME/.cargo/bin:$PATH" && bin/ci`. A change that does not pass it is not proven, whatever its description says.

## Review conventions

- Read-only by default. A write needs an explicit per-grant `query_write` opt-in AND a target-DB role that already holds write privileges; the gateway never provisions them.
- Audit is synchronous: the row commits before the success response goes out, and a failed audit write fails the request. No best-effort audit.
- Every DB call traces to an SSO-verified identity → one `audit_calls` row. A tool that dispatches without its audit row is a blocker, not a nit.
- DB credentials never leave the gateway — not in a response, an error, a log line, an admin endpoint. Read the error and `Debug` paths, not just the happy path.
- Unknown config keys abort boot (`deny_unknown_fields` on `Server`, `Database`, `ServiceAccount`, `Permission`, `Grant`, `Constraints`). A config edit that silently drops a key is a bug.
- One adapter, one pool, per `(server, database)`: a slow query on DB A must never block DB B.
- `get_query_history` filters on the session's `identity.user_sub`, never on a client-supplied field; `limit` is clamped to the ceiling and `truncated` reports that clamp alone.
- The SQL guard denies by default in both modes: DDL, `COPY`, `GRANT`/`REVOKE`, transaction control, multi-statement bodies and `EXPLAIN ANALYZE` are rejected whatever the grant says.
- Hard ceilings: 100,000 rows and 30 s per statement. A grant may tighten them; it may never loosen them.
- Error codes are contract, not prose: `forbidden_sql`, `reason_required`, `timeout`, `rate_limited`, `forbidden`, `invalid_arguments`, `syntax_error`, `unavailable`, `service_overloaded`, `internal`. A changed code is a behaviour change.
- Service accounts are the one exception to per-call SSO verification (spec 14): a `dbmcp_svc_` bearer mapped to exactly one `permissions:` group, audited as `service:<name>`, boot-gated off the admin group, no in-band mint or revoke.
- A behaviour change updates `website/docs/initial-idea/` in the same PR. The spec is canonical; the reviewer's word is the spec's word.

## Gates that matter

- `bin/check` is the gate: `cd` to the repo root, `export PATH="$HOME/.cargo/bin:$PATH"`, then `bin/ci`. The pre-commit hook runs `bin/check`; CI runs the equivalent jobs directly, not `bin/ci` — and its test invocation is wider: `cargo test --all-targets --all-features` where `bin/test` runs `cargo test --all-targets`.
- `bin/ci` = `bin/lint` + `bin/test` + `cargo audit` (skipped with a `— SKIPPED` notice when `cargo-audit` is absent). `bin/test` boots the dev stack (state DB, target DB, MySQL, Mongo) and runs `cargo test --all-targets`; the target DB is never mocked.
- `bin/lint` = `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo clippy --release --all-features -- -D warnings`, `bin/check-scrub-features`.
- CI jobs: `fmt`, `clippy`, `test`, `audit`, `secret-scan`. The first four gate the image build; `secret-scan` is standalone today, so its green is not a required check. `cargo audit` ignores exactly one advisory, `RUSTSEC-2023-0071` — a new ignore is a finding.
- `secret-scan` greps every tracked file OUTSIDE its excluded pathspecs (`tests/**`, `website/**`, `config/example.yaml`, `.github/**`, `src/config/yaml.rs`) for `dbmcp_svc_[0-9a-f]{64}` and fails closed when the grep itself errors. A hit is a leaked service token, not a fixture. The excluded paths get no scan coverage at all, so a credential committed there is invisible to CI.
- The suite is 591 passing tests across 41 binaries. A new MCP tool without an integration test asserting its audit row is incomplete.

## Never flag

- Generated and vendored output only: the Docusaurus build output (`website/build/`, `website/.docusaurus/`, `website/node_modules/` — gitignored, never committed) and vendored artefacts such as `website/package-lock.json`. Everything else under `website/` is authored, not generated: `website/docs/initial-idea/` is the canonical spec and `website/docs/usage/` is public API — review both, and review `.github/workflows/pages.yml` like any other workflow.
- Style a formatter owns: rustfmt (edition 2024, max_width 100, Unix newlines) and clippy's `-D warnings` floor — `bin/lint` decides.
- `bench-harness` and `test-support` off by default, and `benchmarks/results/` gitignored: a benchmark that does not ship is deliberate.
- The `cargo audit` `— SKIPPED` notice in `bin/ci`: the tool was missing on that box, not the audit passed.
- The excluded pathspecs in `secret-scan` (`tests/**`, `website/**`, `config/example.yaml`, `.github/**`, `src/config/yaml.rs`): a token there is a fixture, not a leak — ONLY when it is demonstrably inert (repeated digits, a repeating `0123456789abcdef` run: a placeholder no server ever issued). A plausible, high-entropy `dbmcp_svc_` token in an excluded path is a LIVE credential: report it in EVERY path, excluded or not. The exclusion removes CI coverage; it does not turn a leak into a fixture. CLAUDE.md's credential non-disclosure rule applies to all paths.
- The service-account exception to per-call SSO verification (spec 14): deliberate, audited as `service:<name>` — flag a change that drops the audit contract, not the exception.
- The pinned toolchain in `rust-toolchain.toml` and the SHA-pinned GitHub Actions — deliberate; flag drift between the Dockerfile and the toolchain file, not the pinning itself.
