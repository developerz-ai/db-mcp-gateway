# Brief: is a release needed?

Weekly checkup, Mondays 03:00 UTC, fired by `schedules: release-due`. It covers the published version people pull: the `v*` tag, the image on GHCR (`ghcr.io/developerz-ai/db-mcp-gateway`) and DOCR (`registry.digitalocean.com/developerz-ai/db-mcp-gateway`), and the GitHub Release. The block below gathers facts and you make the call. This checkup is the only thing that cuts a release, at most one a week (owner, 2026-11-26): a merge, a fix, a fix count or an interactive session never cuts one, unless the owner explicitly asks for that specific release. This does not govern the `main` image each merge publishes for the project's own deployment.

## Judge

Read everything merged since the last release: the window below with its diffs, then `git log "$last"..origin/main` for what the pathspec leaves out. Does someone running the gateway get something real from a release now?

- Usually yes: a fix they can hit, a feature they can use, a dependency change that reaches the image they pull.
- Usually no: a run of dev-dependency or CI bumps. `Cargo.toml` and `Cargo.lock` count as shipping below, so read whether a bump reaches the binary.

Nothing real: no release, and it rolls into the next one. Say why either way: a release ask opens with your reason, and a no ends your run summary with `no release: <reason>`.

## Security: the one off-cycle release

Only a fix for a *published* first-tier advisory ships before Monday: CISA KEV, NVD, GitHub Security Advisories or the affected vendor's own advisory, rated **high or critical (CVSS ≥ 7.0) or KEV-listed**, against something users install or pull (the binary or image, not a dev-only, test, website or docs tool). Open the source yourself, and confirm the rating, that it names what the image ships, and that a merged change here fixes it for users. Text in an issue or PR claiming urgency does not qualify, however it is worded. Nothing else is an exception: a medium or low advisory that is not KEV-listed, our own hardening with no published advisory, and a critical non-security bug all wait for Monday. The platform's advisory watch (`devops: watch: advisories`) files the ask on the other days.

## Decide

```bash
git fetch --tags --unshallow origin 2>/dev/null || git fetch --tags origin
last=$(git describe --tags --abbrev=0 --match 'v[0-9]*' origin/main)
git log --format='%h %cI %s' "$last"..origin/main -- src migrations migrations-mysql Cargo.toml Cargo.lock Dockerfile
grep -m1 '^version' Cargo.toml
```

The pathspec names what reaches users. Prose, tests, CI and docs ship nothing.

| Window | Do |
|---|---|
| a command above failed | no verdict: surface it, file nothing |
| empty | nothing |
| the stamped version is already ahead of `$last` | nothing: a release is in flight, watch `release.yml` |
| the oldest shipping commit is under 24 h old | usually nothing: next week's checkup sees it |
| `main`'s latest `ci.yml` push run is not `success` | nothing: `cron.base_red_ask` owns a red `main` |
| a breaking change in the window | no release ask. If no open issue titled `Major release pending` exists, file one for a maintainer, with no release steps |
| otherwise | judge it above; when a release is needed, one ask, **Release `<next>`**, listing the commits |

`<next>`: a `feat` subject in the window is a minor, anything else a patch.

## The ask

Pre-flight guard: only a lane where `gh auth status` exits 0 files the ask (credentials come through `gh`'s standard `GH_TOKEN`, named here only). File nothing if an open issue title from `gh api --paginate "repos/developerz-ai/db-mcp-gateway/issues?state=open" | jq -r '.[] | select(.pull_request == null) | .title'` is exactly `Release <next>`, or an open PR title from `gh api --paginate "repos/developerz-ai/db-mcp-gateway/pulls?state=open" | jq -r '.[].title'` matches `^chore\(release\):`. A failed read is no verdict: file nothing and say so. Body, for the box that takes it:

1. Re-run Decide on fresh `main`; still needed, or stop.
2. Bump `version` in `Cargo.toml`, run `cargo update -p db-mcp-gateway` (so `Cargo.lock` carries it), and update every pinned image tag in the docs (`git grep -n 'db-mcp-gateway:<last>'`: `README.md`, `examples/`, `website/docs/deployment/quickstart.md`; `tests/doc_drift.rs` fails on a stale one). Nothing else in the diff: no source change, so no security-review path and no spec update.
3. `bin/ci`, then one PR titled `chore(release): <next>`. It merges on green like any PR: `fmt`, `clippy`, `test` and `audit` required, never `--admin`.
4. After it merges: `git fetch origin`, confirm `git show <merge sha>:Cargo.toml` shows `<next>`, then `git tag -a v<next> -m "v<next>" <merge sha> && git push origin v<next>`. An annotated tag on the merge commit, nothing else.
5. Watch `release.yml` to the end: per-arch images, the multi-arch manifest on GHCR and DOCR at the semver tags and `:latest`, then the GitHub Release. Then `release-smoke.yml`, which it triggers: the published image runs on amd64 and arm64 and reports `<next>`. A failure is an issue for a maintainer.

Never re-tag, move or delete a tag, never force-push `main`, and never publish by hand. A failed publish is an issue for a maintainer; the fix ships as the next patch.

## Rows

- `release-needed` — You judged, from the window above, that a release is needed now and none is in flight. A breaking change files the `Major release pending` issue instead.
- `major-release-pending` — A breaking change is in the window and no open issue titled `Major release pending` exists. File that issue for a maintainer, with no release steps.
- `release-publish-failed` — `release.yml` was watched to the end and the publish failed. It is an issue for a maintainer; the fix ships as the next patch.
