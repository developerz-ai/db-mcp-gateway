# 01 — Unblock main

> Part of [`overview.md`](overview.md). Depends on: none.
> Done in #376 except the owner's ruleset change (step 5). Instead of a `gate` job, a failed `changes` now runs the Rust jobs; `form_urlencoded` 1.2.3 moves with `url` 2.5.9.

## Files to change
- `Cargo.lock:4713` — `url` 2.5.8 → 2.5.9 (RUSTSEC-2026-0592). `audit` is red on every PR and gates `merge`, so no image ships. **V**
- `.github/workflows/pages.yml:60-112` — upload + deploy in one job; 3 of 40 deploys lost (`No artifacts named "github-pages"`). #371 added only the test; `tests/bin/pages-workflow.test.sh` now exits 1 on clean `main` (105 pass, 6 fail), so `bin/check` and the pre-commit hook fail. **V (executed)**
- `.github/workflows/ci.yml:53` — `git diff --name-only` drops a rename's source path: a test moved to a docs path reads as docs-only. Add `--no-renames`. **R**
- `.github/workflows/ci.yml:113,149,221` — a failed `changes` job skips the required Rust jobs; skipped reads as passed. **R**

## Steps
1. Branch; `cargo update -p url --precise 2.5.9`; diff must touch `url` only (`CLAUDE.md` §Dependency graph). `cargo audit --ignore RUSTSEC-2023-0071` clean. PR, merge first and alone.
2. Second PR: `pages.yml` two jobs exactly as `fixed_layout` in `tests/bin/pages-workflow.test.sh` pins (`build` uploads, `deploy` `needs: build`, `artifact_name: github-pages`, `find -print -quit` guard, no process substitution). Run that script until 0 failed.
3. Same PR: `--no-renames`; a `gate` job (`if: always()`, `needs:` every quality job incl. `changes`, `public-tree`, `secret-scan`) that fails on any result other than `success`, or `skipped` only when `changes` succeeded with `code == false`. Add a `scripts` job running `tests/bin/*.test.sh` (all five) — the gap that let a red guard merge.
4. `merge.needs` gains `public-tree`, `secret-scan`.
5. Owner: make `gate` the single required check in the ruleset, then remove classic protection (SET-3). Order matters: require `gate` before un-requiring the rest.

## Tests
- `bash tests/bin/pages-workflow.test.sh`; `bin/ci`. A throwaway PR with a forced `changes` failure must leave `gate` red.

## Done when
- `weekly` audit and a main push green, `sha-<7>` image published; `bin/check` passes on clean `main`.
