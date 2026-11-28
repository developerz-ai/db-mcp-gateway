# `.dz/`

Repo-scoped configuration for the developerz.ai maintainer agent, under the namespace each config
belongs to. The platform owns the layout. `CLAUDE.md` binds everything here: no file in this tree
relaxes a non-negotiable.

| Path | What |
|---|---|
| `pipeline/agent-pipeline.json` | the agent pipeline: required checks, `ci-only` review gate, standing merge authorization |
| `maintainer/maintainer.yml` | the policy: what the bot triages, closes, reviews, merges and releases. [Reference](https://developerz.ai/docs/maintainer-yml) |
| `maintainer/reviewer.md` | this repo's layer of the developerz.ai reviewer prompt |
| `schedules/` | what each `schedules:` checkup works from, read at `main`'s HEAD when it fires: `release-due.md` (weekly: is a release needed), `improve.md` (first and third Monday: at most three small, evidenced improvements), `docs-drift.md` (lane not registered yet) |
| `onboarding/scorecard.md` | the AI-first scorecard the setup pass writes |

These agent configs stay where the tools that read them look, and nowhere else:

- `.mcp.json`: Claude Code (https://code.claude.com/docs/en/mcp)
- `.claude/`: Claude Code commands, agents, skills, hooks and permissions (`.claude/README.md`)

Docs: https://developerz.ai/docs/maintainer-yml
