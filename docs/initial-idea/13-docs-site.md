# 13 — Docs site + Pages contract

> Status: spec. Locks the published-site shape before more content lands.

## Why this is a spec-level decision

The published site is user-visible surface. The URL layout, the artifact
contents, and the guarantees about what will *never* appear in that artifact
are as much a contract as the MCP tool schema. Follows the same rule as the
gateway itself: nothing sensitive leaves the boundary. Here the boundary is
GitHub Pages instead of an HTTP response.

## Distribution shape

`https://developerz-ai.github.io/db-mcp-gateway/` ships two co-located things
from a single Pages artifact:

- **Landing page** at `/` — hand-authored `docs/site/index.html` +
  `docs/site/llms.txt`.
- **Handbook** at `/docs/` — mdBook-rendered from `docs/**/*.md` listed in
  `docs/SUMMARY.md`.

The uploaded artifact is the whole `docs/site/` directory. mdBook writes into
`docs/site/docs/` (per `book.toml [build] build-dir`) so a single upload
covers both without a separate merge step.

## Source → output

| Source | Output URL | Owner |
|---|---|---|
| `docs/site/index.html` | `/` | hand-authored |
| `docs/site/llms.txt` | `/llms.txt` | hand-authored |
| `docs/SUMMARY.md` | sidebar structure | mdBook |
| `docs/**/*.md` listed in `SUMMARY.md` | `/docs/**/*.html` | mdBook |
| everything else under `docs/` not removed by post-build guardrails | copied to `docs/site/docs/**` verbatim | mdBook recursive-copy |

That last row is the gotcha. mdBook has no allowlist / ignore mechanism; it
copies every non-`.md` file under `src` (= `docs/`) into `build-dir` (=
`docs/site/docs/`) whether `SUMMARY.md` references it or not. See
[mdBook `#1187`](https://github.com/rust-lang/mdBook/issues/1187) and
[mdBook `#2246`](https://github.com/rust-lang/mdBook/issues/2246).
`SUMMARY.md` gates rendering only, not publishing. The post-build guardrails
below (`docs/site/docs/site`, `docs/site/docs/sec`) are stripped before upload
so they never reach the final artifact.

## Guardrails

`.github/workflows/pages.yml` enforces the contract in two post-build steps
before `actions/upload-pages-artifact`:

1. **Strip known recursive-copy leftovers** — `rm -rf docs/site/docs/site
   docs/site/docs/sec` removes the landing page duplicated under
   `/docs/site/` and any WIP notes under `docs/sec/` that aren't referenced
   from `SUMMARY.md`.
2. **Fail on unexpected sensitive/config assets** — scan `docs/site/` for
   files with extensions in a denylist (`.yaml`, `.yml`, `.env`, `.env.*`,
   `.pem`, `.key`, `.toml`, `.sql`) and fail the workflow if any are found.
   The gateway never leaks credentials via the docs artifact either.

Adding a new asset type that legitimately needs to ship (an SVG diagram, a
JS snippet, a CSS file) is fine — those extensions aren't in the denylist.
Adding a config-like asset is not; either move it out of `docs/` or extend
the strip step with an explicit reason.

## `create-missing = false`

`book.toml` sets `create-missing = false` so mdBook fails the build if a
chapter listed in `SUMMARY.md` doesn't exist on disk. Prevents accidental
publishing of empty chapters when a file is renamed or removed without
updating the sidebar.

## Build-dir gitignore

`docs/site/docs/` is gitignored — mdBook writes it in CI and it must never
land in the repo. Committing a stale build would confuse readers about which
version of a page is authoritative.

## Rebuild triggers

The workflow rebuilds and republishes on push to `main` when any of these
change:

- `docs/**`
- `book.toml`
- `README.md`
- `.github/workflows/pages.yml`

No other trigger publishes to Pages. Manual runs are gated behind
`workflow_dispatch`.
