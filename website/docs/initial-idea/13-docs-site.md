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

## Landing shape

The landing at `/` is intentionally minimal — hero + three feature cards,
nothing else. Discovery is driven by the sidebar and the "Get Started"
CTA that jumps to `/docs/deployment/quickstart`. Shape lifted from
`react-redux.js.org`: single centered hero, three-column card row below.

- **Hero** (`website/src/pages/index.tsx`): 🛡️ brand mark inline with the
  product name, one-line subtitle, two CTAs — "Get Started" (primary,
  → quickstart) and "View on GitHub" (secondary, → repo URL from
  `customFields.ghUrl`).
- **Feature cards** (`website/src/components/HomepageFeatures/`): exactly
  three, chosen as the reader-facing summary of CLAUDE.md's five
  Non-negotiables (MUST) — "Credentials never leave the gateway"
  (MUST #1), "Identity, end-to-end" (MUST #2), and "Config-as-code"
  (MUST #5). The remaining two MUSTs — read-only-by-default with no
  gateway-provisioned write grants (MUST #3), and synchronous audit
  where a failed audit write fails the request (MUST #4) — are
  operator-side invariants rather than landing-page pitches; they live
  in `docs/deployment/quickstart` and the audit spec, and the landing
  intentionally does not repeat them. Each card leads with an emoji
  icon (🔒 / 👤 / 📝) wrapped in `aria-hidden="true"` — emoji over an
  icon-font/SVG bundle keeps zero extra asset weight and renders
  consistently on every OS.

Adding a fourth card, a testimonials strip, or any block that isn't in
this section requires a spec update in the same PR — landing shape is a
public surface and drifts silently otherwise.

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

Docusaurus classic theme (stock Infima) with a small, enumerated set of
overrides in `website/src/css/custom.css`:

1. **Brand color scale** — `--ifm-color-primary` and its six
   dark/light shades set to emerald-500 (`#10b981`), plus
   `--docusaurus-highlighted-code-line-bg` tinted to match (light + dark
   variants). Drives buttons, links, sidebar-active, and code-line
   highlights without touching any other Infima surface.
2. **Typography** — `--ifm-font-family-base` set to Inter (with a
   system-font fallback stack) and `--ifm-font-family-monospace` set to
   JetBrains Mono (with `ui-monospace` fallback). So docs pages match the
   landing.
3. **GitHub navbar icon** — `.header-github-link` replaces the "GitHub"
   text label with the mark, via a `mask-image` data-URL SVG that
   inherits `--ifm-navbar-link-color` so it themes cleanly in light and
   dark modes.

Everything else — hero surfaces, feature-card layout, dark-mode
palette — inherits from Docusaurus's default theme. Both light and dark
modes ship; dark is the default so the initial render matches the
brand. Same visual model as `react-redux.js.org`: stock Docusaurus,
brand-color swap, nothing invasive on top.
