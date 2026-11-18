# Brief: is the project healthy?

Weekly checkup (Mondays 07:00 UTC) fired by `schedules: health`: the failures no issue or PR announces.

| Signal | Command | Healthy |
|---|---|---|
| `main` is green | `gh run list --workflow ci.yml --branch main --event push --limit 1 --json conclusion,headSha,url`, then `git rev-parse origin/main` | `success` on the `origin/main` tip; a null conclusion or another sha is no verdict |
| the last tag published | `t=$(git describe --tags --abbrev=0 --match 'v[0-9]*' origin/main); gh run list --workflow release.yml --limit 5 --json conclusion,headSha,url` against `git rev-parse "$t^{commit}"` | `success` on that sha; no run on that sha is no verdict |
| the stamped version is tagged | `grep -m1 '^version' Cargo.toml` against `$t` | equal, or an open release PR or in-flight run explains it |
| the GitHub Release exists | `gh release view "$t" --json isDraft,publishedAt` | not a draft, published |
| Dependabot is not stuck | `gh pr list --app dependabot --state open --limit 100 --json number,updatedAt,statusCheckRollup` | no PR with failed checks and more than 7 days since `updatedAt` |

## What to file

For each unhealthy signal, one ask, unless an open issue already carries its exact title. Read the
open titles first, exactly so: `gh api --paginate "repos/developerz-ai/db-mcp-gateway/issues?state=open" | jq -r '.[] | select(.pull_request == null) | .title'`,
then compare byte for byte (a search can miss a title; the paginated listing cannot). A failed read is no verdict, never "no open ask".
Titles are stable: nothing that changes run to run (sha, run URL, version) goes in one; that goes in the body,
with the command and its output. Unreadable evidence is no verdict: re-run it, never file it as a defect.
A red `main` comes first: nothing releases from it. For `last-tag-published`, a red `release-smoke.yml`
run on that tag (`gh run list --workflow release-smoke.yml --limit 5 --json conclusion,event,url`) is the
same defect seen after the publish: name it in that ask's body, never as a second ask.

This lane reads and files; it never repairs. It never re-runs a publish, re-tags, moves or deletes a tag,
pushes an image by hand, force-pushes `main` or merges with `--admin`. Recovery is a maintainer's.

## Rows

- `main-green` — The latest `ci.yml` push run on the `origin/main` tip is `success`; a null conclusion or another sha is no verdict.
- `last-tag-published` — The last `v*` tag on `origin/main` has a `success` `release.yml` run on its own sha; no run on that sha is no verdict.
- `stamped-version-tagged` — `version` in `Cargo.toml` equals that tag, or an open release PR or an in-flight release run explains it.
- `github-release-published` — The GitHub Release for that tag is published and not a draft.
- `dependabot-not-stuck` — No open Dependabot PR has failed checks with more than 7 days since its `updatedAt`.
