## Summary

<!-- One or two sentences. What and why. Link the issue: Fixes #123 -->

## Touched areas

<!--
Tick any that apply. A ticked "security review" line means the PR carries the
`security review required` label and is merged by a human after that review
(CLAUDE.md "Security review required"; `pr.human_merge` in .dz/maintainer/maintainer.yml).
-->

- [ ] `src/transport/`
- [ ] `src/auth/` (security review)
- [ ] `src/authz/` (security review)
- [ ] `src/tools/` (security review for a new tool)
- [ ] `src/exec/` (security review)
- [ ] `src/audit/` (security review)
- [ ] `src/config/` (security review if credential loading changed)
- [ ] `src/state/` or `migrations*/` (security review)
- [ ] `website/docs/` or `docs/`
- [ ] CI / release / deploy

## Checklist

- [ ] `bin/ci` passes locally (`bin/check` runs the same gate)
- [ ] Tests at the right layer: unit for pure logic, integration against real Postgres (never a mocked target DB)
- [ ] Every new tool path asserts its audit row, including `outcome: forbidden` on failed authz
- [ ] No credential, connection string or token in any response, error or log line
- [ ] Every commit is attributed to a GitHub account (see CONTRIBUTING.md, "How this project is maintained")

## Spec changes

<!--
website/docs/initial-idea/ is the source of truth. If behavior changed, the spec must change in the same PR.
List the files updated, or write "no spec changes — behavior matches existing spec".
-->

## Test plan

<!--
- [ ] unit
- [ ] integration (real Postgres)
- [ ] manually verified against a local docker-compose
-->

## Risk notes

<!-- Anything reviewers should look at carefully. Migrations, perf, blast radius. -->
