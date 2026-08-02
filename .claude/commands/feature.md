---
description: End-to-end feature/bug-sweep workflow for db-mcp-gateway — understand, diagnose against a real deployment, explore in parallel, split into layer-disjoint slices, build with a hive of parallel agents in this one checkout (never worktrees), gate with bin/ci against real Postgres, PR (security-review-labelled where required), squash-merge, release on a v* tag. Tracks in GitHub issues. Reads intent from the prompt.
argument-hint: <what you want built or fixed, plain language> [+ reference URL(s)]
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Agent, Task, SendMessage, TaskCreate, TaskUpdate, TaskList, Skill, WebFetch, mcp__codegraph, mcp__glitchtip
---

# /feature

You are a **senior engineer on the db-mcp-gateway team**. Take a feature or a bug sweep from plain-language idea to merged-and-healthy. This is a self-hosted MCP gateway giving AI agents audited, SSO-gated, read-only DB access, and it **never holds a DB credential on the client side** — read `CLAUDE.md` and the spec in `website/docs/initial-idea/` before designing anything.

**Done means merged and verified — nothing less counts.** The arc: understand → diagnose → explore → slice → build → gate green → PR → **merged** → **CI's image build confirmed** → (**tagged + released**, if that's the ask) → **original symptom re-checked** → issues and spec left true. A green local gate is not done; an open PR is not done. When you report, say which of those you actually verified rather than which you assume happened.

## Request
$ARGUMENTS

**The prompt is the context — read the intent.** How autonomous to be, how big the scope, whether to confirm before merging: infer it from the words. "Do full work" / "just ship it" → run start-to-finish, decide everything yourself, merge on green, no check-ins — surface decisions in the issue and PR body instead of asking. A tentative or exploratory ask → clarify what's genuinely ambiguous and let the user review before you merge. Don't make the user configure you. The flow below is a map, not a checklist to recite — but always stop for a true blocker: any CLAUDE.md Non-negotiable at risk, a credential-leak path, an authz bypass, a missing audit row, a destructive action against a real database.

**Pick the PR mode before you brief anyone.** **Slice-per-PR** (default) — one layer's concern per PR, merged one at a time. **One fat PR** ("do it in 1 PR") is the user's call and legitimate for a coherent sweep: layer-disjointness still governs the *build* (it is how parallel agents avoid clobbering each other), it just stops governing the *commit*, and the body must then carry the finding-by-finding ledger the sub-issues would have.

**Cap a PR at ~110–120 files.** Past that it loses the checks that catch things. **CodeRabbit refuses outright above 150 changed files**, so the biggest, riskiest PR gets the *least* automated review — backwards, and this repo leans on that review for auth/authz/audit. A human can't hold 279 files either, so approval becomes a formality. One red CI job blocks everything: fmt, clippy, a `test` job with four DB service containers and `cargo audit` all gate, so one failing integration test holds ~90 fixes hostage. And a bisect lands on one enormous squash commit. **Split even if the user asked for one PR, and say why** — the agents' file sets were disjoint by construction, so each becomes a PR for free. Land the shared primitive (an error variant, a newtype, a state-DB migration) first, then the consumers.

## Work as a hive mind, in one checkout

**Whether to hive at all is a judgement call, not a ritual.** Two things justify it: **searching** (a broad sweep where you want conclusions, not file dumps) and **scale** (independent, layer-separable work that would take hours serially). Nothing else. A single-file fix, one clippy warning, one bug with an obvious home in `src/authz/` — do it yourself; briefing, collision management and report-reading cost more than the change, and you pay that in the one context that must survive to the merge.

When you do hive, a big task is not one agent doing more; it is a **team sharing one working tree**, with you as coordinator. **Never use git worktrees** — no `isolation: worktree`, no per-agent directories, ever. The cost here is concrete: one `target/` dir (a second checkout means a full cold rebuild, and cargo takes an exclusive build lock on it anyway), one `.env`, one `docker-compose.dev.yml` stack — a single `state-db`, `target-db`, `permissions-mysql` and `target-mongo` for everybody.

- **You coordinate; you do not code.** You own git, the ledger and the merge, and are the only participant who must survive to the end — spend that context on routing, not on reading files an agent will report back. Editing `src/` yourself means you took a slice from someone who had room for it.
- **The file set is the lock.** Every brief names that agent's exclusive paths *and* what every other live agent holds. The `CLAUDE.md` layer table is the natural cut — `src/transport/`, `auth/`, `authz/`, `tools/`, `exec/`, `audit/`, `config/`, `state/` each have one reason to change. An agent needing a file it doesn't own **stops and reports the collision** — never edits across the line, never negotiates peer-to-peer; you mediate. `src/errors.rs` is touched by nearly everything: give it to exactly one agent, or keep it.
- **Agents are long-lived teammates.** New work in a layer someone holds goes to them via `SendMessage`, keeping their context and their file lock. A second agent on the same paths = two writers, a lost fix.
- **Work in waves; each wave re-tasks the next.** Wave 1's findings decide wave 2's slices; a mid-run user report (step 6) can re-task a live agent immediately. Don't plan wave 3 before wave 1 reports — it will be wrong.
- **Keep a visible ledger.** `TaskCreate`/`TaskUpdate` per slice, so ownership survives a context handoff.
- **Expect the hive to contradict you.** A good agent reports "premise H1 is false — the constraint merge already takes the minimum, `src/authz/…:88`". Drop the premise. Findings that survive several independent readers are the ones worth shipping.

### Who runs which checks

**No agent runs `bin/test`, `bin/ci`, or a bare `cargo test`.** `bin/test` is `cargo test --all-targets` over the whole crate *and* brings the docker stack up. Run N times concurrently it does not parallelise — cargo serialises on the `target/` build lock, and whichever runs get through then fight over one `state-db`. Biggest time sink in a parallel run here.

| | Agent (per iteration) | Coordinator (once, at the end) |
|---|---|---|
| format | `cargo fmt -- <files it edited>` | `cargo fmt --all -- --check` (in `bin/lint`) |
| lint | `cargo clippy --all-targets --all-features -- -D warnings`, **once when otherwise done** — one cargo target, so clippy is crate-wide by nature; this is the floor | `bin/lint`, which adds the `--release` clippy pass catching imports used only under `cfg(test)` |
| tests | `cargo test --test <its own integration test>` / `cargo test <module::path>` — named explicitly, never bare | `bin/ci` (`bin/lint` + `bin/test` + `cargo audit`), in the **background** |

An agent owns *its own files and its own tests*; whole-crate green is the coordinator's job and nobody else's.

**DB-backed tests share one database and `serial_test` will not save you.** `#[serial]` serialises real-DB tests *within one cargo process*; two agents in two cargo processes defeat it and truncate the same `state-db` under each other — the symptom is wandering failures naming tables the test never writes. There is no per-worker-DB knob here; the isolation mechanism is scheduling. **Exactly one participant runs DB-backed tests at a time** — give those suites to one agent or hold them for your own final gate, and read any integration failure with this in mind.

### Two things only the coordinator can do

- **Every slice you NAME, you must dispatch.** A named-but-unlaunched slice makes agents dutifully defer work to a teammate who does not exist, and that work vanishes. Keep roster and dispatched set as one list; reconcile before you read any report.
- **Reserve an "unowned" bucket and expect to fill it mid-run.** The fix often lands where no slice covers: `src/errors.rs`, the `main.rs` wiring, a `config/example.yaml` field, a `src/state/` migration, the spec. A homeless finding is the one most likely to be quietly dropped — when a report says "the real fix is outside my set", assign it immediately, don't file it.
- **Look for causal chains across reports.** Agents see their own layer; only you see all of them. A cancellation that never reaches `pg_cancel_backend` and a missing `outcome: cancelled` audit row are one defect seen from two layers, not two. Spend one pass asking "does A explain B?" — it changes what you fix and what you can drop.

## The flow

1. **Understand.** Restate the goal in a line and name which Non-negotiables it touches: credentials never leave the gateway; every DB call → SSO identity → audit row; read-only by default (writes need per-grant opt-in **and** a target-DB write role — the gateway never provisions write grants); audit is synchronous; permissions by YAML-PR or the SSO-gated admin API, never an in-band UI. URLs in the ask → `WebFetch`, extract the *mechanism*, translate onto this stack (Rust, tokio, axum, sqlx, hand-rolled JSON-RPC over HTTP+SSE).

2. **Distrust the paperwork.** Check any spec page or status note against the code and `git log` before planning work off it. Specs and status notes go stale: this repo has drifted before, and a page describing the target is not evidence the target shipped. Merged PR titles are the cheapest ground truth. State plainly which claims you falsified, so nobody re-implements shipped work or "fixes" working code.

3. **Diagnose against a real deployment — early, not at the end.** Evidence beats reasoning and costs one command. All read-only:
   - `mcp__glitchtip` — the org's error tracker (`glitchtip.infra.developerz.ai`); an existing issue usually names the module and the release.
   - The **audit log** is the best forensic surface this product has: no matching row, or `outcome: forbidden`/`cancelled`, tells you which layer bailed. `bin/dev psql state` reads it locally; for a deployed instance ask the operator rather than reaching for a credential.
   - `/metrics` and the JSON `tracing` output — every tool dispatch is a span with `request_id`, `user`, `server`, `database`.
   - Reproduce locally: `bin/dev up`, then `cargo run -- --config config/example.yaml`.

   **Never run a mutating statement against anyone's database**, and never paste a connection string, password or role secret into a report — that leak is the bug class this product exists to prevent. A finding with a real fingerprint outranks one derived from reading alone.

4. **Explore (parallel).** Fan out `Agent` Explore agents (very thorough; `codegraph_explore` — this repo has a `.codegraph/` index — for structure) over **disjoint** areas so reports don't overlap. Require of every finding: severity, `file:line`, a one-sentence defect statement, and a **concrete failure scenario** (inputs → wrong outcome). Demand two more things explicitly: the spec claims they **falsified**, and the premises of yours that turned out **true**, so you neither re-fix working code nor re-verify settled ground. Produce a ranked worklist; log what the survey couldn't cover. **Protect your own context** — don't read what an agent will report; prefer one thorough agent over three shallow ones plus your own reading.

5. **Track in GitHub issues — search before you create.** `gh issue list --search "<area>"`, open *and* recently closed. Three outcomes beat a fresh ticket: already tracked, partly tracked (add a checklist item to the existing parent so history stays in one place), or a closed issue already decided what you're about to re-decide. Create the parent *after* exploration so it carries real content — `file:line` findings, the GlitchTip fingerprint, the deferred list. One checklist item per slice; each PR carries `Fixes #NNN`. Don't close the parent until every PR is merged.

6. **Fold in live user reports as first-class findings.** A mid-run client trace, transcript or log line is *confirmed against a real deployment* and routinely outranks the audit's own findings. Reproduce, root-cause, rank above equal-severity read-only findings. If an in-flight agent owns those files, extend its brief with `SendMessage` rather than spawning a second agent onto the same paths.

7. **Build — branch first, then fan out.** Before a single agent starts, get off `main` while the tree is clean:

   ```bash
   git fetch origin && git status --short   # expect clean
   git checkout -b <type>/<slug>            # fix/ feat/ test/ refactor/ docs/
   ```

   Then fix slice boundaries **before launching anyone**, each file set disjoint from every other. Two agents that must edit one file are ONE slice — combining is honest, splitting invents a boundary that doesn't exist. Multi-layer work goes bottom-up (state/migration → exec → authz → tools → transport), and a shared primitive (error variant, newtype, migration) **lands first**; then every consumer adopts it. Never convert N call sites N ways.

   Every brief carries all nine of these; omitting one is how a run goes wrong:
   - **its exclusive file set**, and never to edit outside it;
   - **which other agents are live on which paths**, so a collision is *reported*, not silently resolved;
   - each finding with `file:line`, the defect and the concrete failure scenario — plus permission to **drop any finding the code contradicts** (that is the agent working correctly);
   - **evidence first, diagnosis second** — symptom, GlitchTip fingerprint or missing audit row, failing input; *then* your hypothesis, explicitly labelled unverified, to confirm or kill *before* building. Briefs that lead with a confident root cause send agents to the wrong file;
   - the house constraints binding its layer: typed errors (`thiserror`; `anyhow` only at the `main.rs` boundary) with a stable client code, no `unwrap`/`expect` outside `main`/tests, newtypes over bare primitives and illegal states unrepresentable, borrow by default, async end-to-end (no `std::sync` guard across `.await`, `spawn_blocking` for blocking work), per-DB pools never shared across `(server, database)`, cancellation-safe paths, `tracing` not `println`, files ≤300 LOC;
   - **tests ship with the code, failure case first** — unit tests for pure logic (authz eval, config validation, SQL rewriting) with no DB, `proptest` for constraint merge (most restrictive always wins), **never mock the target DB in a query-path test**, and every integration test hitting a tool asserts an audit row;
   - **checks narrowed to its OWN files** (table above) — never a crate-wide suite, and DB-backed suites only if it is the one agent holding them;
   - **no git operations at all** — no branch, commit, checkout or stash; the coordinator owns all git and work is left uncommitted;
   - **never tell an agent to "ask me" — it cannot.** A subagent has no channel to the user, so a question is a dead end: it blocks or guesses. Give it two legal moves: **decide and flag** (act on the most defensible reading, state the assumption, mark the artifact so you can overwrite it), or **stop and report** with evidence when either path would be unsafe or wasted. Then *you* take it to the user and re-task with `SendMessage`, which resumes the agent with its full context.

   Small feature → one agent, skip the fan-out.

8. **Verify, then PR + merge.** The bar is `bin/ci` green — `bin/lint` (fmt-check, `clippy --all-targets --all-features -D warnings`, **and** the `--release` clippy pass), `bin/test` (unit + integration against real Postgres/MySQL/Mongo), `cargo audit`. Run it **once**, in the **background**; it is minutes long and a foreground call looks hung. Green gate **plus audit rows actually asserted** is the bar — if it isn't logged, it didn't happen.

   **Before committing, sweep the agents' leftovers**: scratch `.rs` probes at the repo root, stray `dbg!`/`println!`, a temp YAML config, commented-out tests. Agents create them and rarely clean up.

   **Let every agent finish, then plain git** — you are already on the branch from step 7:

   ```bash
   git fetch origin                    # did main move? see below
   git add <this slice's paths>        # then git status --short, and READ it
   git commit && git push -u origin HEAD
   ```
   Naming paths on `git add` is all the selectivity needed. **Never `git stash`** — one global stack shared with every concurrent agent; you will pull in someone else's work. For slice-per-PR, repeat one slice at a time, re-`git fetch`ing after each merge.

   **Main moves under you.** `git fetch` and intersect *files changed on main* with *files changed locally*; a real overlap is **three-way merged** (`git merge-file -p ours base theirs`), never taken wholesale — a naive tree build drops main's lines silently, with no conflict marker.

   `gh pr create` with Summary + Test plan. Add the **`(security review required)`** label when the PR touches `src/auth/`, `src/authz/`, credential loading/storage, the audit write path, any new MCP tool, or SQL execution (timeouts, row caps, cancellation), and say in the body what reviewers check: credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection, timeout bypass. A behavior change updates `website/docs/initial-idea/` in the **same PR**; anything under `website/docs/usage/` is a public-API change.

   Then `claudetm merge-pr <pr>` — it waits for CI, fixes failures, addresses review comments (CodeRabbit included) and merges when green. It operates on the **current directory**, so at most one PR is in flight at a time: parallel *building* is fine, parallel *merging* is not. **When every check already passes prefer `gh pr merge --squash`** — `claudetm` can hang on an already-green PR. Gotcha: **0 registered checks reads as "pass"** — wait for a plausible count *and* zero pending, or it merges RED right after a rebase. Never force-push `main`; never `--no-verify` (fix the hook).

9. **Ship: image on merge, release on tag** — two different things, and only one is automatic.
   - **On merge to `main`**, `ci.yml` builds per-arch images and pushes a multi-arch manifest to **GHCR and DOCR** under the short-SHA and `main` tags; the ArgoCD Image Updater in `developerz-ai/infrastructure` tracks the DOCR tag. Confirm the `build` + `merge` jobs went green and the short-SHA tag exists — that, not the merge, is what rolls.
   - **A release is a `v*` tag.** `vX.Y.Z` runs `release.yml`: multi-arch build → GHCR + DOCR at semver + `:latest` → a GitHub Release operators pull. Only cut a tag when asked, then confirm the workflow ran and the image is publicly pullable.
   - **Never edit `developerz-ai/infrastructure` from here.** A new runtime env var goes in `.env.example` + `config/example.yaml` + a PR-body callout for a human to mirror; a real infra change is a separate PR in that repo.

10. **Watch + close.** CI green, GlitchTip clean in the feature area, audit log correct — every DB call traced to an SSO identity, no credential in any response, log or error. **Re-verify the original symptom is gone** using whatever proved it in step 3. `Fixes #NNN` auto-closes each child; verify each flipped, close stragglers by hand with a link to the PR, then close the parent yourself. Broken → forward-fix on a branch. Credential leak, authz bypass or audit gap → stop and tell the user.

11. **Leave the trail straight.** Update the spec pages your change invalidated — a doc that lies costs the next person a full re-audit. When a defect could recur, land the mechanical guard in the same PR: a `proptest` invariant, a boot-time config validation, an integration test asserting the audit row.

## Hard rules (from CLAUDE.md — non-negotiable)

DB **credentials never leave the gateway** — not in a response, log, error or admin endpoint; never return a connection string, password or role secret. **Every DB call traces to an SSO-verified identity → audit row.** **Read-only by default** — writes need per-grant opt-in AND a target-DB write role; the gateway never provisions write grants; never run as DB superuser. **Audit is synchronous** — it commits before the success response; audit fails → request fails; never skip it for performance. **Permissions live in YAML reviewed by PR or come via the SSO-gated admin API** (audited to `permissions_audit`) — **no admin web UI, ever**. No "service account" path without a permissions group + audit identity; never promote one user's session to another. Typed errors, no `unwrap` outside `main`/tests, files ≤300 LOC, one reason to change per layer, no premature abstraction (trait on the *second* impl), no backwards-compat shims pre-v1. Never mock the target DB in query-path tests. Never force-push `main`, never `--no-verify`, never `git stash`. Single-tenant only. NOT building: BI tool, query builder, credential vault, SaaS, LLM, agent runtime.

## Output

Report what shipped, and be equally explicit about what didn't — a sweep that fixes 40 of 90 findings is a success only if the other 50 are named.

```
Root cause:  <the one-line mechanism, for a bug sweep>
Primitive:   <name> @ <path>  (PR #NNN, merged)          [sweeps only]
Layers:      <n> touched (transport/auth/authz/tools/exec/audit/config/state)
Fixed:       <n> findings across <m> PRs → #… #…    sec-review label: <yes/no>
Deferred:    <n> — <what, and why not now>               [never omit this line]
Falsified:   <spec/doc claims that were wrong, now corrected>
Guards:      <proptest invariant / boot validation / audit assertion, or none>
Verify:      bin/lint clean · bin/test green (real PG) · cargo audit clean · audit rows asserted
Ship:        <CI short-SHA image / v-tag → GHCR+DOCR / none>   env asks: <VAR… or none>
Verified:    <the symptom, re-checked>   GlitchTip: <clean?>
Issues:      #<parent> closed (<k> children)
```
