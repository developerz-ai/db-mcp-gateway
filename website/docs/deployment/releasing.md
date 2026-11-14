# Releasing

Releases are triggered by a `v*` git tag. The `.github/workflows/release.yml` workflow then:

1. **Preflight.** Fails the release before any build when the tag (minus its `v`) differs from the `version` in `Cargo.toml`, so an image never reports a version other than its tag. It also decides which moving tags this release may move (below).
2. Builds the image natively per architecture (amd64 + arm64) and stitches one multi-arch manifest.
3. Tags it `X.Y.Z` and, where preflight allows, `X.Y`, `X` and `latest`.
4. Pushes the same tag set to two registries: `ghcr.io/developerz-ai/db-mcp-gateway` (the public artifact) and a DigitalOcean Container Registry mirror (the in-cluster source the ArgoCD Image Updater tracks).
5. Creates a GitHub Release with auto-generated notes.

GHCR is the public distribution channel because this is an open-source project — public images are free, unmetered for pulls, and don't have Docker Hub's rate limits.

### Moving tags only move forward

`X.Y.Z` is always pushed. The moving tags move only when this tag is the highest released semver in their line, ranked over every `vX.Y.Z` tag in the repository:

| Tag | Moves when the release is the highest… |
|---|---|
| `latest` | of all releases |
| `X` | in major `X` |
| `X.Y` | in minor `X.Y` |

So a backport `v1.6.1` pushed after `v2.0.3` gets `1.6.1`, `1.6` and `1`, but `latest` stays on `2.0.3`. The GitHub Release's "Latest" badge (`make_latest`) follows the same rule. Prereleases move none of them.

## Cutting a release

`main` takes changes through pull requests only — no direct pushes.

```bash
# 1. Bump the version on a branch and open a PR
git switch -c release/X.Y.Z
sed -i '0,/^version = .*/s//version = "X.Y.Z"/' Cargo.toml
cargo update -w
git add Cargo.toml Cargo.lock
git commit -m "chore(release): X.Y.Z"
gh pr create --fill

# 2. After the PR is merged, tag the merge commit on main and push the tag
git switch main && git pull
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Watch the workflow at `https://github.com/developerz-ai/db-mcp-gateway/actions`. When it finishes:

- `ghcr.io/developerz-ai/db-mcp-gateway:X.Y.Z` is pullable.
- `ghcr.io/developerz-ai/db-mcp-gateway:latest` points at it, if it is the highest release.
- A GitHub Release exists with the changelog.

## Versioning

Semver. Pre-1.0 we don't promise compat between minors — `0.x.y` to `0.(x+1).0` may break config schema, MCP tool surface, or audit log shape. The release notes will call out any break.

Post-1.0:

- Patch (`1.2.3` → `1.2.4`) — no behavior changes a config has to react to.
- Minor (`1.2.x` → `1.3.0`) — additive only: new tools, new config keys (always with safe defaults), new sinks.
- Major (`1.x.y` → `2.0.0`) — breaking change. Documented migration path in release notes.

## Prereleases

`v1.2.3-rc1`, `v1.2.3-beta1` etc. push with the literal tag (`1.2.3-rc1`) and **do not** move `latest`, `X` or `X.Y`. `Cargo.toml` must carry the same prerelease version, or preflight fails. Use these for previews against a staging gateway.

## Image provenance

The image is built from a clean checkout of the tagged commit by GitHub Actions. No SLSA provenance or signature is attached yet: the workflow holds no `id-token: write` permission, and adding provenance is on the roadmap.

## Yanking a release

Don't delete tags. To pull a broken release out of circulation:

1. Cut the next patch with the fix.
2. `latest` moves to the new patch automatically on tag push, as long as it is the highest release.
3. Note the yank in the next release's notes.

Deleted tags break anyone who pinned to that version. Cutting a forward fix is always safer.
