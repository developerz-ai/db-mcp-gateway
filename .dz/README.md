# `.dz/`

The developerz.ai maintainer bot's configuration for this repo. The platform owns the layout.

| Path | What |
|---|---|
| `maintainer/maintainer.yml` | the policy: what the bot triages, closes, reviews, merges and releases. [Reference](https://developerz.ai/docs/maintainer-yml) |
| `briefs/` | what each `schedules:` checkup works from, read at `main`'s HEAD when it fires: `release-due.md` (weekly: is a release needed), `security-release.md` (the one off-cycle release: a confirmed security fix), `health.md` (the failures nothing announces), `improve.md` (monthly: at most three small, evidenced improvements) |
