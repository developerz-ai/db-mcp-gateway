# Releasing

Releases are triggered by a `v*` git tag. The `.github/workflows/release.yml` workflow then:

1. Builds a multi-arch (amd64 + arm64) container image.
2. Tags it: `v1.2.3` → `1.2.3`, `1.2`, `1`, plus `latest` (unless the tag is a prerelease like `v1.2.3-rc1`).
3. Pushes to `ghcr.io/developerz-ai/db-mcp-gateway`.
4. Creates a GitHub Release with auto-generated notes.

GHCR is used because this is an open-source project — public images are free, unmetered for pulls, and don't have Docker Hub's rate limits.

## Cutting a release

```bash
# 1. Bump version in Cargo.toml
sed -i 's/^version = .*/version = "X.Y.Z"/' Cargo.toml
cargo update -w
git add Cargo.toml Cargo.lock
git commit -m "release: X.Y.Z"

# 2. Tag and push
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main vX.Y.Z
```

Watch the workflow at `https://github.com/developerz-ai/db-mcp-gateway/actions`. When it finishes:

- `ghcr.io/developerz-ai/db-mcp-gateway:X.Y.Z` is pullable.
- `ghcr.io/developerz-ai/db-mcp-gateway:latest` points at it.
- A GitHub Release exists with the changelog.

## Versioning

Semver. Pre-1.0 we don't promise compat between minors — `0.x.y` to `0.(x+1).0` may break config schema, MCP tool surface, or audit log shape. The release notes will call out any break.

Post-1.0:

- Patch (`1.2.3` → `1.2.4`) — no behavior changes a config has to react to.
- Minor (`1.2.x` → `1.3.0`) — additive only: new tools, new config keys (always with safe defaults), new sinks.
- Major (`1.x.y` → `2.0.0`) — breaking change. Documented migration path in release notes.

## Prereleases

`v1.2.3-rc1`, `v1.2.3-beta1` etc. push to GHCR with the literal tag (`1.2.3-rc1`) but **do not** update `latest`. Use these for previews against a staging gateway.

## Image provenance

The image is built from a clean checkout of the tagged commit by GitHub Actions. The workflow runs with `id-token: write` so we can attach SLSA provenance to the image later (not wired in phase 0 — see roadmap).

## Yanking a release

Don't delete tags. To pull a broken release out of circulation:

1. Cut the next patch with the fix.
2. Update GHCR `latest` to the new patch (automatic on tag push).
3. Note the yank in the next release's notes.

Deleted tags break anyone who pinned to that version. Cutting a forward fix is always safer.
