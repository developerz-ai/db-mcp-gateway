# .github/ — CI standard and release lane

The job table, then the rules for editing anything here.

## Jobs

GitHub Actions on GitHub-hosted runners — `ubuntu-latest` default (`ubuntu-24.04-arm` for arm64). `test` runs against `docker-compose.dev.yml` (state + target Postgres, MySQL, Mongo, Redis, Dragonfly) — the stack `bin/test` uses locally — started in the background so its boot overlaps the compile. Rust jobs install the toolchain `rust-toolchain.toml` pins with the runner's `rustup` (no `dtolnay/rust-toolchain`); jobs with a rust-cache uninstall the runner's `stable`, because rust-cache keys on every installed toolchain. `bin/ci` reproduces `ci.yml` locally.

| Job | Does |
|---|---|
| `fmt` | `cargo fmt --check`; every action pinned to a 40-hex SHA |
| `changes` | path filters emit `code` (docs-only PRs — `website/**`, `docs/**`, `.claude/**`, `*.md`, never `.dz/**` — skip the Rust jobs), `deps` (lock, manifests, audit config), `image` (Dockerfile, `.dockerignore`, Cargo, `src/`, migrations, `third_party/`, `config/example.yaml`; PRs only), `msrv` (manifests + lock), `website` (`website/`, `README.md`; PRs only). A job skips only on an explicit `false`, so a failed `changes` runs them all |
| `clippy` | `clippy -D warnings` twice on one `--profile ci` graph: `--all-targets`, then lib + bins with `-C debug-assertions=off` (the shipping cfg); plus `bin/check-scrub-features` |
| `test` | `cargo nextest run --profile ci --cargo-profile ci --all-targets --all-features` (`--no-run` first, then after the dev stack is healthy); JUnit uploaded (`.config/nextest.toml`) |
| `yugabyte` | `bin/test-yugabyte` against `yugabytedb/yugabyte:2.25.2.0-b359` (the version a production deployment runs; compose profile `yugabyte`, YSQL on 5435); the Postgres query-path `it_db` modules listed in nextest's `yugabyte` profile (a new module is absent until added there), minus the NOTIFY tests YB ignores |
| `audit` | `cargo audit` (`cargo-audit` pinned) — only when `deps` changed (H8: an advisory blocks only the PR that can fix it) |
| `secret-scan` | advisory — `git grep -nE` over every tracked file for `dbmcp_svc_[0-9a-f]{64}`; exempt paths: `tests/**`, `website/**`, `config/example.yaml`, `.github/**`, `src/config/yaml/**` |
| `public-tree` | `python3 -I .github/scripts/public_tree.py` on every PR, docs-only included (no `changes` gate): no internal host, private repo, private CI provider, setup-mode name or home path in any tracked file; rules pinned by `test_public_tree.py` |
| `scripts` | every `tests/bin/*.test.sh` and every `.github/scripts/test_*.py` |
| `image-check` | PRs where `image` is true: Dockerfile build, amd64, no push, reads `main`'s gha cache |
| `msrv` | `cargo +<rust-version from Cargo.toml> check --locked` when `msrv` is true |
| `website` | `npm ci`, typecheck, build when `website` is true |
| `gate` | `if: always()`, needs every quality job; green only on success or a skip `changes` ordered (`.github/scripts/ci_gate.py`). The single required check once the owner retires the rest (SET-3) |
| `build` + `merge` | on `main`: per-arch image → multi-arch manifest, pushed to GHCR **and** DOCR. `merge` (writes `sha-<7>` + `main`) needs `build`, `gate` and every quality job, and runs only when `build` and `gate` succeeded. `tests/` is out of the Docker context (`.dockerignore` is an allowlist) |
| `audit` (`audit.yml`) | daily `cargo audit` on `main`; a failure opens or updates the "cargo audit fails on main" issue, a clean run closes it |
| `weekly` (`weekly.yml`) | Mondays: `cargo update --dry-run` report + `load-gate` |
| `release` (`release.yml`) | on `v*`: `preflight` → `reuse` waits for `ci.yml`'s push run on the tagged commit and, when green, `merge` re-tags its `sha-<7>` manifest (per-arch digests = the tested ones; release version/revision/source as index annotations); red CI blocks the release; no CI run (or a missing image) falls back to the per-arch `build` with a warning, reading `main`'s gha layer cache but never writing one |
| `workflow-lint` (`workflow-lint.yml`) | advisory — actionlint (pinned image digest) + the hook tests (`python3 -I .claude/hooks/test_hooks.py`) on PRs and `main` pushes touching `.github/workflows/**`, `.github/scripts/**` or `.claude/hooks/**` |
| `release-smoke` (`release-smoke.yml`) | advisory, post-publish — after each successful `release`, Tuesdays on the Latest release, and by hand: pulls the published GHCR image per arch (amd64 + arm64), checks its platform and that `--version` reports the tag, and on the scheduled run that `:latest` is the Latest release |

`timeout-minutes` is ~2× measured p95 (clippy 15, test 20, small jobs 5, CI image build 30; the release per-arch build 60 for a cold compile). `ci.yml` cancels superseded **PR** runs only — `main` pushes get a per-SHA group and never cancel, because the Image Updater pins the short SHA and a cancelled run would leave that commit with no image (`main` is a moving convenience tag).

## Rules

- **The gate.** What blocks a merge is whatever GitHub enforces live, and that is the only authority: the rulesets (`gh api repos/developerz-ai/db-mcp-gateway/rulesets`, then each by id) **and** classic branch protection (`gh api repos/developerz-ai/db-mcp-gateway/branches/main/protection`), which still exists until the owner retires it (SET-3). Never re-declare the required-check list as fact in a doc; `.dz/maintainer/maintainer.yml` names it only so the agent knows whose red check it is. `ci.yml`'s `gate` job is built to be the single required check; the decision is `.github/scripts/ci_gate.py`.
- **Skipped means passed.** GitHub counts a skipped required job as passing. `ci.yml`'s path filters rely on that: `changes` emits `code`/`deps`/`image`/`msrv`/`website`, and a filtered job skips only on an explicit `false` (a failed `changes` runs them all). `gate` re-checks every skip against `changes`' outputs, and `ci_gate.py`'s table must name every job in `gate.needs` (the gate fails red otherwise). A job-level `if:` is still a decision, not a convenience: a new skip condition is a merge that ran nothing.
- **Runners.** GitHub-hosted only (public repo): `ubuntu-latest`, `ubuntu-24.04-arm` for native arm64. No self-hosted runners, so a fork PR never reaches persistent hardware.
- **Pins.** Every `uses:` is a 40-hex SHA with the version in a trailing comment; `ci.yml`'s `fmt` job and `bin/ci` (so `bin/check`) both fail an unpinned ref under `.github/workflows/`. Tools installed by `taiki-e/install-action` carry an exact version (`cargo-audit@…`, `cargo-nextest@…`). Copy a pin already used in another workflow before adding a new one; Dependabot keeps them fresh (`dependabot.yml`, 14-day cooldown). Docker images run by a step are pinned by digest.
- **Least privilege.** Top-level `permissions: contents: read`; a job that needs more asks for it itself. `persist-credentials: false` on every checkout.
- **Concurrency and timeouts.** Every workflow declares a `concurrency` group and every job sets `timeout-minutes`. `ci.yml` cancels superseded PR runs, and its `main` pushes get a per-SHA group so they never cancel; `release.yml`, `pages.yml`, `weekly.yml`, `audit.yml` and `release-smoke.yml` never cancel, on any event.
- **Caches.** Saved from `main` only (pushes and `ci.yml`'s Monday warm run); PRs restore. Rust keys carry the ISO week; `test` and `yugabyte` share one key that only `test` saves. Node's `~/.npm` is saved by `pages.yml` on `main` and restored by `ci.yml`'s `website` job.
- **The release tag is the input.** `release.yml` fires on a `v*` tag pushed onto the merge commit of a `chore(release)` PR, checks it against `Cargo.toml`, waits for `ci.yml`'s push run on that commit and re-tags its tested `sha-<7>` manifest (red CI blocks the release; building per arch only when no CI run or image exists), and cuts the GitHub Release. A published tag is never moved or deleted; a broken release ships as the next patch (`.dz/schedules/release-due.md`). `release-smoke.yml` then pulls what was published and checks it runs.
- **Lint workflows before pushing.** `workflow-lint.yml` runs actionlint on every change here. Locally: `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.7 -no-color`.
- **Secrets.** Two secrets, each read in one place: `DOCR_TOKEN` in the image-push jobs (`ci.yml` `build`/`merge`, `release.yml`), and `PUBLIC_TREE_PRIVATE_WORDS` in `ci.yml`'s `public-tree` job. Beyond them, the run's own `GITHUB_TOKEN` logs in to GHCR in the push jobs and files the advisory issue in `audit.yml` (`issues: write`, that job alone). A new secret is read in the one job that needs it, never at workflow level.
