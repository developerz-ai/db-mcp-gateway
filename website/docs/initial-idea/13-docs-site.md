# 13 — Docs site + Pages contract

> Status: spec. Locks the published-site shape.

## Why this is a spec-level decision

The published site is user-visible surface. The URL layout, the artifact
contents, and the guarantees about what will *never* appear in that artifact
are as much a contract as the MCP tool schema. Follows the same rule as the
gateway itself: nothing sensitive leaves the boundary. Here the boundary is
GitHub Pages instead of an HTTP response.

## Distribution shape

`https://developerz-ai.github.io/db-mcp-gateway/` ships two co-located things
from a single Pages artifact:

- **Landing page** at `/` — React component at `website/src/pages/index.tsx`.
- **Handbook** at `/docs/` — Docusaurus-rendered from Markdown under
  `website/docs/`, structured by `website/sidebars.ts`.

The uploaded artifact is the whole `website/build/` directory produced by
`docusaurus build`. Docusaurus emits landing and docs together; no separate
merge step.

## Source → output

| Source | Output URL | Owner |
|---|---|---|
| `website/src/pages/index.tsx` | `/` | hand-authored React |
| `website/static/llms.txt` | `/llms.txt` | hand-authored |
| `website/static/img/**` | `/img/**` | logo + favicon assets |
| `website/sidebars.ts` | sidebar structure | Docusaurus |
| `website/docs/**/*.md` reachable from `sidebars.ts` | `/docs/**` | Docusaurus |
| files under `website/static/**` | copied to site root verbatim | Docusaurus |

Docusaurus does not perform mdBook-style recursive copies of the source docs
directory. Only `sidebars.ts`-referenced markdown gets rendered, and only
files under `website/static/` get copied verbatim.

## Guardrails

`.github/workflows/pages.yml` enforces the contract in one post-build step
before `actions/upload-pages-artifact`:

**Fail on unexpected sensitive/config assets** — scan `website/build/` for
files with extensions in a denylist (`.yaml`, `.yml`, `.env`, `.env.*`,
`.pem`, `.key`, `.toml`, `.sql`) and fail the workflow if any are found.
The gateway never leaks credentials via the docs artifact either.

Adding a new asset type that legitimately needs to ship (an SVG diagram, a
JS snippet, a CSS file) is fine — those extensions aren't in the denylist.
Adding a config-like asset is not; either move it out of `website/static/`
or extend the guard step with an explicit reason.

## `onBrokenLinks: 'throw'`

`docusaurus.config.ts` sets `onBrokenLinks: 'throw'` and
`onBrokenMarkdownLinks: 'throw'` so a rename that breaks an internal doc
link fails the build instead of shipping a dead link. Same guarantee as
mdBook's `create-missing = false`, tighter — Docusaurus checks every
markdown-to-markdown link resolves too.

## Build-dir gitignore

`website/build/` and `website/.docusaurus/` are gitignored — Docusaurus
writes them during the build, and they must never land in the repo.
Committing a stale build would confuse readers about which version of a
page is authoritative.

## Rebuild triggers

The workflow rebuilds and republishes on push to `main` when any of these
change:

- `website/**`
- `README.md`
- `.github/workflows/pages.yml`

No other trigger publishes to Pages. Manual runs are gated behind
`workflow_dispatch`.

## Editing docs

The navbar "Edit this page" link points at the current file in `main`.
Contract: `editUrl: https://github.com/developerz-ai/db-mcp-gateway/edit/main/website/`.
Rename a markdown file → the edit link automatically follows the new path
next build.

## Theme

Palette + typography match the landing page (shadcn/Vercel-inspired zinc-950
+ emerald-500 accent, Inter + JetBrains Mono). Overrides live in
`website/src/css/custom.css` on top of Docusaurus's Infima framework.
Both light and dark modes are styled; dark is the default so the initial
render matches the brand.
