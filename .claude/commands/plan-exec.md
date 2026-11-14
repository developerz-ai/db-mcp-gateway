---
description: Execute a /planx plan dir wave by wave — status.yml as the ledger, one PR per wave, ≤4 agents with disjoint file sets, human rows never decided silently.
argument-hint: <plan dir, e.g. docs/plans/2026/11/12/101-…> [extra scope]
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Agent, Task, SendMessage, Skill
---

# /plan-exec

You are the **coordinator** executing a plan written by `/planx`. `/feature`'s hive rules (`.claude/commands/feature.md`) bind you: one checkout, no worktrees, ≤4 agents at once, only you spawn, only you touch git, one PR in flight. This file adds what a multi-wave plan needs on top.

## Request
$ARGUMENTS

## 1. Read the plan as a ledger
- `overview.md` (waves, risks, done-when), `status.yml` (what is already done), any human-decisions file.
- Two plans for the same work (an "Overlap" note)? Pick one as plan of record, mark the other `superseded`, fold its unique rows in, and say so in both `status.yml` files.
- Re-verify before trusting: plan line refs drift, "inferred" rows need a reproducing test first, and a row may already be done (agents find stale premises — accept "premise false, here is the line").

## 2. Run a wave
- One wave = one branch off fresh `main` = one PR. Create the branch yourself before any agent starts; agents never switch it.
- Cut file sets along the `CLAUDE.md` layer table (`src/transport/`, `auth/`, `authz/`, `tools/`, `exec/`, `audit/`, `config/`, `state/`). A shared primitive (error variant, newtype, state-DB migration) lands in the wave before its consumers.
- Brief each agent with: its plan rows by ID, its **exclusive file set**, every other live agent's file set, "no git, no spawning, no worktrees", "checks narrowed to your own files and tests (`cargo test --test <name>`), never `bin/test` or `bin/ci`", "finish the slice; a blocker is a report", and a **"DX friction"** section in its report. At most one agent runs DB-backed tests at a time: they share one `state-db`.
- Agents never edit `CLAUDE.md`, `.claude/`, `.dz/` or `.github/workflows/`: they report proposed text and you apply it. Spec edits under `website/docs/initial-idea/` ride with the code that changes the behaviour.
- Read-only surveys (perf ideas, inventories) can run while a wave builds: they feed later waves, never the current PR.

## 3. Before the PR
- An agent's change that contradicts an earlier recorded decision (a brief under `.dz/`, a `CLAUDE.md` rule, a dated `status.yml` decision) is reverted, not merged: the earlier human call wins until a human changes it.
- Apply the agents' patches for files they did not own, sweep their leftovers (scratch files, `dbg!`, temp configs), then `bin/ci` once, in the background. Stage by path, ≤100 files.
- A wave touching a `CLAUDE.md` security-review path gets the `security review required` label and waits for a human merge (`pr.human_merge` in `.dz/maintainer/maintainer.yml`).
- PR body claims only what the diff does; evidence you lack is listed as missing.

## 4. After the merge
- Confirm merged → `git checkout main && git pull` → clean tree. Read the `ci.yml` run on `main` you triggered, and the image build it publishes.
- Update `status.yml`: slice `status`/`percent`, an `evidence:` line per merged PR or verified deploy, `current_focus` for the next wave. Commit it with the next wave's PR, never alone.
- Deploys: verify in the target (the running version, a probe passing), not from a green run. Releases follow `.dz/briefs/release-due.md`: a `chore(release)` PR alone, the `v*` tag on its merge commit after it lands, never moved or deleted.

## Human rows
Breaking changes (tool surface, error codes, config schema, audit shape), security calls, secrets only the owner holds, anything weakening a `CLAUDE.md` non-negotiable: never decide them. Record a recommendation and the blocker in `status.yml`. When the owner decides in-session, record it as a dated decision (`by: <owner>`) next to the guard or doc it changes.

## Output
Per wave: PR link + merge state, rows done, rows deferred with reason, deploy/release evidence, open human rows.
