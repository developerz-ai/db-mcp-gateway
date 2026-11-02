# Brief: is the project healthy?

Daily checkup fired by `schedules: health`: the failures no issue or PR announces.

| Signal | Command | Healthy |
|---|---|---|
| `main` is green | `gh run list --workflow ci.yml --branch main --event push --limit 1 --json conclusion,headSha,url`, then `git rev-parse origin/main` | `success` on the `origin/main` tip; a null conclusion or another sha is no verdict |
| the last tag published | `t=$(git describe --tags --abbrev=0 --match 'v[0-9]*' origin/main); gh run list --workflow release.yml --limit 5 --json conclusion,headSha,url` against `git rev-parse "$t^{commit}"` | `success` on that sha; no run on that sha is no verdict |
| the stamped version is tagged | `grep -m1 '^version' Cargo.toml` against `$t` | equal, or an open release PR or in-flight run explains it |
| the GitHub Release exists | `gh release view "$t" --json isDraft,publishedAt` | not a draft, published |
| Dependabot is not stuck | `gh pr list --app dependabot --state open --limit 100 --json number,updatedAt,statusCheckRollup` | no PR with failed checks and more than 7 days since `updatedAt` |

## What to file

For each unhealthy signal, one ask, unless an open issue already carries its exact title
(`gh issue list --state open --search "<title> in:title" --json number,title`, then compare byte for byte).
Titles are stable: nothing that changes run to run (sha, run URL, version) goes in one; that goes in the body,
with the command and its output. Unreadable evidence is no verdict: re-run it, never file it as a defect.
A red `main` comes first: nothing releases from it.

## Rows

- `main-green` — The `ci.yml` push run on the `origin/main` tip is `success`; a null conclusion or another sha is no verdict.
- `last-tag-published` — The `release.yml` run on the last tag's sha is `success`; no run on that sha is no verdict.
- `stamped-version-tagged` — The `version` stamped in `Cargo.toml` equals the last tag, or an open release PR or in-flight run explains it.
- `github-release-published` — The GitHub Release for the last tag is not a draft, and it is published.
- `dependabot-not-stuck` — No open Dependabot PR has failed checks and more than 7 days since `updatedAt`.
