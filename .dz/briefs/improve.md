# Brief: monthly improvement

Fired every Monday by `schedules: improve`. **Act only on the first Monday of the month:**
`[ "$(date -u +%-d)" -le 7 ]`. On any other Monday stop here, file nothing, open nothing.

Once a month, leave the gateway measurably better. `CLAUDE.md` binds every change, and `non_goals` in the policy file are off limits. A red `main`,
a missing publish and a stuck Dependabot PR belong to `health`.

## Signals

| Signal | Command |
|---|---|
| the gate on fresh `main` | `bin/ci` |
| advisories | `cargo audit` |
| dependency majors | `cargo outdated` if installed, else the Dependabot PRs closed red |
| open bugs | `gh issue list --state open --label bug --json number,title,url` |
| the weekly lanes (`audit`, `outdated`, `load-gate`) | `gh run list --workflow weekly.yml --limit 4 --json conclusion,url,createdAt` |
| the post-publish smoke | `gh run list --workflow release-smoke.yml --limit 4 --json conclusion,event,url,createdAt` |

Read the failing job's log before deciding anything. A red run whose log names a missing secret or a
repository setting is the owner's to fix: escalate once, never delete the check or turn it into a green skip.

## Pick at most three, in this order

1. Anything the gate found broken or flaky: the root cause, never a retry or a skip.
2. Advisories, then dependency majors Dependabot could not land, one per PR.
3. Open bugs, each starting from a test that fails on `main`.
4. Spec and docs drift: `website/docs/initial-idea/` is the canonical spec, and a behaviour change updates it in the same PR. `.dz/schedules/docs-drift.md` lists which guards exist and what they leave uncovered.
5. Hidden failures: an `|| true`, a `2>/dev/null`, a `continue-on-error`, an `if let Err(_) = … {}` or `.ok()` that drops an error, a test that skips in CI. Make it fail, or handle it visibly (a typed error, a `tracing` event, a test that pins it). A documented, deliberate fallback stays; give it a reason comment if it has none.
6. Speed: the `load-gate` lane's report against `benchmarks/baselines/`. A change counts only with numbers from `benchmarks/gateway_overhead.sh` on `main` and on the branch, on the same runner class. Never at the cost of a non-negotiable: audit stays synchronous.
7. Simplification: dead code, duplicated logic, a file past the 300-LOC cap, slow or flaky tests.

## Ship

One small PR per improvement, its evidence in the body, `bin/ci` green first. A PR touching a CLAUDE.md security-review path (`src/auth/`, `src/authz/`, credential loading or storage, the audit write path, `src/tools/`, SQL execution) carries the `security review required` label and waits for a human merge (`pr.human_merge`). Never bump the version, and never touch release automation, audit semantics or grant handling from this checkup: open an issue instead. A breaking change is never merged by this lane (`escalate.ask_before_acting: [breaking_change]`): open the PR or issue and leave it for a maintainer.
Check no open PR or issue already covers it. If nothing is worth changing, do nothing: no empty PRs, no churn.

## Rows

- `gate`: `bin/ci` on fresh `main` finds something broken or flaky; address the root cause, never a retry or a skip. A red `main` belongs to `health`.
- `advisories`: `cargo audit` finds advisories; prioritize them before dependency majors, one per PR.
- `dependency-majors`: `cargo outdated` if installed, else the Dependabot PRs closed red, identifies dependency majors Dependabot could not land; one per PR. A stuck Dependabot PR belongs to `health`.
- `open-bugs`: `gh issue list --state open --label bug --json number,title,url` identifies open bugs, each starting from a test that fails on `main`.
- `spec-drift`: Spec drift under `website/docs/`; a behaviour change updates the spec in the same PR.
- `weekly-lanes`: `weekly.yml`'s `audit`, `outdated` and `load-gate` runs on `main`; read a red run's log before acting, and a missing secret or setting is escalated once, never skipped.
- `release-smoke`: `release-smoke.yml` runs; a red one on the Latest release is `health`'s `last-tag-published` ask, not a second one.
- `hidden-failures`: swallowed errors and CI skips, made visible; a documented deliberate fallback stays.
- `speed`: a measured improvement from the load gate, numbers from both sides on one runner class.
- `simplification`: dead code, duplicated logic, files past 300 LOC, slow or flaky tests.
