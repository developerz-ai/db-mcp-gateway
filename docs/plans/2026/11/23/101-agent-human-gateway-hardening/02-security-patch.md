# 02 — Security patch (2.3.1)

> Part of [`overview.md`](overview.md). Depends on: 01. Label: `security review required`.

Rows, files, steps and tests are in the owner's private notes (full slice text there). Nothing about them goes in this repository before the release.

## Steps
1. Owner decides H1; branch names and PR text stay neutral.
2. Failing real-DB test per row, then the fix; spec updated in the same PR.
3. `chore(release)` 2.3.1 alone, tag, same day as the merge.
4. After the release: replace this stub with the slice.

## Done when
- Every private row closed with a test that failed before it; 2.3.1 on both registries.
