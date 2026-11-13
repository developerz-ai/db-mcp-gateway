# `.dz/`

Repo-scoped configuration for the developerz.ai maintainer agent, under the namespace each config
belongs to. The platform owns the layout. `CLAUDE.md` binds everything here: no file in this tree
relaxes a non-negotiable.

| Path | What |
|---|---|
| `pipeline/agent-pipeline.json` | the agent pipeline: required checks, `ci-only` review gate, standing merge authorization |
| `maintainer/maintainer.yml` | the policy: what the bot triages, closes, reviews, merges and releases. [Reference](https://developerz.ai/docs/maintainer-yml) |
| `maintainer/reviewer.md` | this repo's layer of the developerz.ai reviewer prompt |
| `briefs/` | what each `schedules:` checkup works from, read at `main`'s HEAD when it fires: `release-due.md` (weekly: is a release needed), `security-release.md` (the one off-cycle release: a confirmed security fix), `health.md` (weekly: the failures nothing announces), `improve.md` (monthly: at most three small, evidenced improvements) |
| `schedules/` | briefs for lanes not registered yet (`docs-drift.md`) |
| `onboarding/scorecard.md` | the AI-first scorecard the setup pass writes |

Two agent configs stay at the repository root, because the tools that read them look there and
nowhere else:

- `.coderabbit.yaml`: CodeRabbit (https://docs.coderabbit.ai/configure-coderabbit)
- `.mcp.json`: Claude Code (https://code.claude.com/docs/en/mcp)

Docs: https://developerz.ai/docs/maintainer-yml
