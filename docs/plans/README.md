# docs/plans

Execution plans written by `/planx` (`.claude/commands/planx.md`) and run by `/plan-exec`, one directory per plan: `docs/plans/<YYYY>/<MM>/<DD>/<1NN>-<slug>/`.

**This repository is public, so every plan here is a public document.** A plan describes changes to this repository's code, specs and CI. A slice that measures or changes a running deployment — its resources, its database grants and roles, its accounts, its network policy, who can reach it — is written in that deployment's own repository, never here; a plan here may say only that such a slice exists. The same goes for the platform's side of a change.

Completed plans are removed once their follow-ups are tracked elsewhere; the history keeps them.
