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

## Pick at most three, in this order

1. Anything the gate found broken or flaky: the root cause, never a retry or a skip.
2. Advisories, then dependency majors Dependabot could not land, one per PR.
3. Open bugs, each starting from a test that fails on `main`.
4. Spec and docs drift: `website/docs/initial-idea/` is the canonical spec, and a behaviour change updates it in the same PR. `.dz/schedules/docs-drift.md` lists which guards exist and what they leave uncovered.

## Ship

One small PR per improvement, its evidence in the body, `bin/ci` green first. A PR touching a CLAUDE.md security-review path (`src/auth/`, `src/authz/`, credential loading or storage, the audit write path, `src/tools/`, SQL execution) carries the `security review required` label and waits for a human merge (`pr.human_merge`). Never bump the version, and never touch release automation, audit semantics or grant handling from this checkup: open an issue instead. A breaking change is never merged by this lane (`escalate.ask_before_acting: [breaking_change]`): open the PR or issue and leave it for a maintainer.
Check no open PR or issue already covers it. If nothing is worth changing, do nothing: no empty PRs, no churn.

## Rows

- `gate`: `bin/ci` on fresh `main` finds something broken or flaky; address the root cause, never a retry or a skip. A red `main` belongs to `health`.
- `advisories`: `cargo audit` finds advisories; prioritize them before dependency majors, one per PR.
- `dependency-majors`: `cargo outdated` if installed, else the Dependabot PRs closed red, identifies dependency majors Dependabot could not land; one per PR. A stuck Dependabot PR belongs to `health`.
- `open-bugs`: `gh issue list --state open --label bug --json number,title,url` identifies open bugs, each starting from a test that fails on `main`.
- `spec-drift`: Spec drift under `website/docs/`; a behaviour change updates the spec in the same PR.
