# Brief: do the docs still say what their guards prove?

This file is the brief a `docs-drift` lane would read (`.dz/schedules/docs-drift.md`). No
`docs-drift` schedule is registered today: `.dz/maintainer/maintainer.yml` registers only
`release-due`, `security-release`, `health` and `improve`, so nothing fires this brief until one is
registered there with `brief_file: .dz/schedules/docs-drift.md`. Until then `improve.md` reads it
as the registry of which docs guards exist.

This lane is read-only. It reads the tree and reports; it never edits a file, never deletes one,
never commits, and it files nothing.

`website/docs/initial-idea/` is the canonical spec (CLAUDE.md: a behaviour change updates the spec
in the same PR). No check proves the spec still describes the code; the guards below prove links,
anchors and one table's shape. That gap is the reason this brief exists.

## What counts as a guard

A guard protects the claim it actually checks — a link resolves, an anchor exists, a table and
its row list agree — never the truth of the prose around it. Register a check against that claim,
and write `none` where nothing protects a surface at all.

## Surfaces and their guards

| Surface | Guard | What it protects |
|---|---|---|
| `website/docs/**` path links | `onBrokenLinks: 'throw'` and `onBrokenMarkdownLinks: 'throw'` in `website/docusaurus.config.ts`, run by `npm run build` in `.github/workflows/pages.yml` (PRs touching `website/**` or `README.md`) and by `bin/ci`'s Pages job | that a link path resolves to a page — not what the page says |
| `website/docs/**` heading fragments | `tests/bin/doc-anchors.test.sh`, run by `bin/ci` only (not by `ci.yml` or `pages.yml`) | that every `#fragment` matches a heading ID the build renders — not the heading's content |
| the Pages artifact | the sensitive-asset denylist step in `.github/workflows/pages.yml` | that no `*.yaml`, `*.env`, `*.pem`, `*.key`, `*.toml` or `*.sql` file ships in the site build — not the docs' content |
| `.dz/briefs/health.md` | `tests/brief_rows.rs` | that the signal table and its `## Rows` list agree in count, order and names — not that a command still works |
| `website/docs/initial-idea/**` (spec) | none | no test reads it; only the review lane's `path_instructions` and CodeRabbit's spec rule ask for a same-PR update |
| `website/docs/usage/**`, `website/docs/deployment/**` | none beyond the link and anchor guards above | an env var, port, flag or error code named there is checked by no test |
| `README.md`, `CONTRIBUTING.md`, `CLAUDE.md` | none | no test reads them; `README.md`'s version line is bumped by the `chore(release)` PR by hand |
| `.dz/briefs/{release-due,security-release,improve}.md`, this file | none | no test reads them |

## Relations no check covers

- **The spec against the code.** Error codes in `03-mcp-tools.md`, config keys in `08-config.md`,
  the audit shape in `07-logging-retention.md`: nothing compares them with `src/`. A mismatch is a
  drift finding under the spec surface, with the file and line on both sides.
- **`docs-only` CI skip and the brief guard.** A PR that changes only `.md` files skips the `test`
  job (`ci.yml` `changes` filter), so `tests/brief_rows.rs` does not run on a PR that edits only
  `.dz/briefs/health.md`. It runs on the next push to `main` and in `bin/ci`.
- **Anchors in CI.** `tests/bin/doc-anchors.test.sh` runs in `bin/ci` alone; a broken fragment
  merged without a local `bin/ci` run surfaces only as a Docusaurus build warning.

## Out of scope

- Generated and vendored output: `website/build/`, `website/.docusaurus/`, `website/node_modules/`,
  `website/package-lock.json`.
- `docs/` (internal notes) and `docs/plans/**`: working notes, not published docs.

## Reading the tree

```bash
# Read-only: the surfaces this checkup looks at, and the guards that cover them.
ls website/docs/initial-idea/ website/docs/usage/ website/docs/deployment/
grep -n 'onBroken' website/docusaurus.config.ts
grep -n 'doc-anchors' bin/ci .github/workflows/*.yml
```

## Reporting

One finding per surface and guard, never the same finding twice: a drift is reported under the
surface it drifted in and the guard that stopped covering it, so a later run recognises its own
finding instead of reporting it anew. A surface with no guard is reported as unguarded, not as
drift: an absent guard is a fact about the registry, not a sentence that has gone stale.

## Rows

- `spec-vs-code` — The spec under `website/docs/initial-idea/` still matches `src/` for error codes, config keys and audit shape; no test guards it.
- `link-paths` — Docusaurus `onBrokenLinks` / `onBrokenMarkdownLinks: 'throw'` still guard `website/docs/**` link paths.
- `heading-anchors` — `tests/bin/doc-anchors.test.sh` still guards fragments, and still runs only from `bin/ci`.
- `pages-artifact` — The Pages sensitive-asset denylist still runs before upload.
- `health-brief-rows` — `tests/brief_rows.rs` still pins `.dz/briefs/health.md`'s table and rows.
- `unguarded` — The surfaces listed `none` are still unguarded; report them as such, not as drift.
