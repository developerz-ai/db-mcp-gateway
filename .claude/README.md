# .claude/

| Path | What it is |
|---|---|
| `commands/feature.md`, `commands/planx.md`, `commands/plan-exec.md` | `/feature` takes a change to merged; `/planx` writes a plan for another agent; `/plan-exec` runs a plan wave by wave |
| `agents/` | Layer agents (`mcp-transport`, `authz-permissions`, `query-exec`, `audit-log`), one per `CLAUDE.md` layer they own |
| `skills/` | `stack` (dev stack), `state-migrations`, `verify-change` (the pre-commit proof) |
| `settings.json` | Permissions and hooks. Personal overrides go in `settings.local.json` (gitignored) |
| `hooks/` | Python 3 stdlib, no packages. A box without `python3` skips them |

Every agent and skill file carries the marker `owned by this repository's maintainers`; `tests/public_tree.rs` fails a file without it.

## Hooks

**`guard_bash.py`, before every Bash call, about 20ms.** Refuses `--no-verify`, a force-push to `main`, `git worktree add`, moving or deleting a published `v*` tag (`git tag -d/-f`, `git push --delete`, a forced or `:`-prefixed tag refspec), `gh pr merge --admin`, `gh release delete`, `docker push` of the gateway image, and `pkill -f` with a pattern that matches its own shell. Creating and pushing a new `v*` tag is allowed: the release lane does that after the `chore(release)` PR merges (`.dz/briefs/release-due.md`). It reads the command's words, not quoted text, and fails open on anything it cannot parse. It is a seatbelt, not a sandbox: `bash -c "git push -f origin main"` gets past it.

**`post_edit.py`, after every Edit or Write.** `rustfmt --check` on an edited `.rs` file, about 50ms; a diff in that file goes back to the agent. Advice only, never a block (the edit has already happened): the security-review label on a `CLAUDE.md` security path, a spec update for `src/tools/`, `src/config/`, `src/transport/`, never editing a committed migration, the 300-LOC cap, the release-PR rule on `Cargo.toml`, the `tests/brief_rows.rs` guard on `.dz/briefs/health.md`, `actionlint` on workflows and `shellcheck` on `bin/` scripts. A missing tool or a timeout never fails anything.

## If a hook refuses something legitimate

The refusal goes to the agent, with the reason, and nothing else happens.

1. Read the reason. Most refusals have a narrower command that passes: a feature branch, a `[b]racket` pattern, a new patch tag instead of a moved one.
2. If the action is right, a person runs it in their own terminal, or starts the session with `DBMCP_HOOKS_OFF=1 claude`. Prefixing the refused command does nothing: the hook reads the session's environment, not the command's.
3. Fix the false match in `guard_bash.py` in its own PR, with the command that was wrongly refused in the PR body.

An agent never edits a hook to get its own command through, and never rewrites a command to dodge one.
