# .devin/

| File | What |
|---|---|
| `blueprint.yaml` | Devin's environment: the pinned Rust toolchain, `cargo-nextest`, `cargo-audit` and the dev stack's images baked into the snapshot; `bin/dev up` per session; the repo's check commands as knowledge |
| `autofix-enabled` | Layer 2 of the Devin auto-fix kill-switch (below) |

## Devin auto-fix kill-switch

`autofix-enabled` is **Layer 2** of the Devin auto-fix kill-switch. The Devin `glitchtip-autofix` playbook reads this file as its **first step** and no-ops the run if the value is `false` — no Devin API access required to stop it.

- **`true`** — auto-fix runs may proceed (still gated by the Devin schedule being enabled and the L1/L4 switches on the infrastructure side).
- **`false`** — pause: the next scheduled run stops immediately.

**To pause Devin auto-fix on this repo:** set the contents of `autofix-enabled` to `false` and commit.
