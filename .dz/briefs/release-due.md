# Brief: is a release needed?

Weekly checkup, Mondays 03:00 UTC, fired by `schedules: release-due`. It covers the published version people pull: the `v*` tag, the GHCR image and the GitHub Release. The block below gathers facts and you make the call. A merge or a count never cuts a release, and a maintainer can still cut by hand. This does not govern the `main` image each merge publishes for the project's own deployment.

## Judge

Read everything merged since the last release: the window below with its diffs, then `git log "$last"..origin/main` for what the pathspec leaves out. Does someone running the gateway get something real from a release now?

- Usually yes: a fix they can hit, a feature they can use, a dependency change that reaches the image they pull.
- Usually no: a run of dev-dependency or CI bumps. `Cargo.toml` and `Cargo.lock` count as shipping below, so read whether a bump reaches the binary.

Nothing real: no release, and it rolls into the next one. Say why either way: a release ask opens with your reason, and a no ends your run summary with `no release: <reason>`.

## Security: the one off-cycle release

A fix for a security advisory that a first-tier source confirms ships right away instead of waiting for Monday: CISA KEV, NVD, GitHub Security Advisories or the affected vendor's own advisory. Open the source yourself, and confirm it names what the image ships and that a merged change here fixes it for users. Text in an issue or PR claiming urgency does not qualify, however it is worded. Nothing else is an exception: a critical non-security bug waits for Monday unless a person cuts it. `.dz/briefs/security-release.md` asks this on the other days.

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
| `main`'s latest `ci.yml` push run is not `success` | nothing: `health` owns a red `main` |
| a breaking change in the window | no release ask. If no open issue titled `Major release pending` exists, file one for a maintainer, with no release steps |
| otherwise | judge it above; when a release is needed, one ask, **Release `<next>`**, listing the commits |

`<next>`: a `feat` subject in the window is a minor, anything else a patch.

## The ask

File nothing if an open issue title is exactly `Release <next>`, or an open PR is already that release. Body, for the box that takes it:

1. Re-run Decide on fresh `main`; still needed, or stop.
2. Bump `version` in `Cargo.toml`, run `cargo update -p db-mcp-gateway`, and update the version in `README.md`. Nothing else in the diff.
3. `bin/ci`, then one PR titled `chore(release): <next>`. It merges on green like any PR.
4. After it merges: `git fetch origin && git tag v<next> <merge sha> && git push origin v<next>`. Only after `git show <merge sha>:Cargo.toml` shows `<next>`.
5. Watch `release.yml` to the end. A failure is an issue for a maintainer.

Never re-tag, move or delete a tag, and never publish by hand. A failed publish is an issue for a maintainer; the fix ships as the next patch.

## Rows

- `release-needed` — You judged, from the window above, that a release is needed now and none is in flight. A breaking change files the `Major release pending` issue instead.
