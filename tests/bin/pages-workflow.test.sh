#!/usr/bin/env bash
# Pin the Pages build/deploy artifact-handoff contract with local fixtures:
# .github/workflows/pages.yml is a protected merge-gate file, so the repair is
# a handoff for an owner. These fixtures stay self-contained and green on the
# unrepaired checkout; the owner's workflow edit is gated by its own checks.
set -euo pipefail
cd "$(dirname "$0")/../.."

pass=0
failed=0

ok() {
  pass=$((pass + 1))
}

bad() {
  printf 'FAIL: %s\n' "$1"
  failed=$((failed + 1))
}

assert_has() {
  local label=$1 file=$2 needle=$3
  if grep -qF -- "$needle" "$file"; then ok; else bad "$label: missing '$needle'"; fi
}

assert_lacks() {
  local label=$1 file=$2 needle=$3
  if grep -qF -- "$needle" "$file"; then bad "$label: unexpected '$needle'"; else ok; fi
}

# Order matters: the guard has to run on the same tree that gets uploaded.
guard_precedes_upload() {
  local file=$1 guard upload
  guard=$(grep -nF 'Guard Pages artifact against sensitive assets' "$file" | head -n 1 | cut -d: -f1)
  upload=$(grep -nF 'actions/upload-pages-artifact@' "$file" | head -n 1 | cut -d: -f1)
  [[ -n $guard && -n $upload && $guard -lt $upload ]]
}

# deploy must be a separate job that waits for the upload to finish; the
# v5.0.1 deploy-pages client lists artifacts once, with no retry.
fixed_layout() {
  local file=$1
  grep -qF 'needs: build' "$file" &&
    grep -qF 'build:' "$file" &&
    grep -qF 'deploy:' "$file" &&
    grep -qF 'actions/upload-pages-artifact@' "$file" &&
    grep -qF 'actions/deploy-pages@' "$file" &&
    guard_precedes_upload "$file" &&
    grep -qF 'name: github-pages' "$file" &&
    grep -qF 'artifact_name: github-pages' "$file" &&
    grep -qF 'path: website/build' "$file"
}

check_contract() {
  local label=$1 file=$2
  assert_has "$label" "$file" 'actions/checkout@'
  assert_has "$label" "$file" 'npm ci'
  assert_has "$label" "$file" 'npm run typecheck'
  assert_has "$label" "$file" 'npm run build'
  assert_has "$label" "$file" 'Guard Pages artifact against sensitive assets'
  assert_has "$label" "$file" 'actions/configure-pages@'
  assert_has "$label" "$file" 'actions/upload-pages-artifact@'
  assert_has "$label" "$file" 'actions/deploy-pages@'
  assert_has "$label" "$file" 'github.event_name != '"'"'pull_request'"'"''
  assert_has "$label" "$file" 'permissions:'
  assert_has "$label" "$file" 'id-token: write'
  assert_has "$label" "$file" 'name: github-pages'
  assert_has "$label" "$file" 'path: website/build'
  if guard_precedes_upload "$file"; then ok; else bad "$label: guard must precede upload"; fi

  # The eight case-insensitive denylist extensions are the whole guard. Drop
  # any one and a sensitive asset could be published.
  local pattern
  for pattern in '*.yaml' '*.yml' '*.env' '.env.*' '*.pem' '*.key' '*.toml' '*.sql'; do
    assert_has "$label denylist" "$file" "$pattern"
  done
  assert_has "$label" "$file" '-iname'
  # The find status must be captured directly. Process substitution runs find
  # in a subshell, so its status is lost and an unreadable build passes.
  assert_has "$label" "$file" 'status=$?'
  assert_lacks "$label" "$file" '< <('
  assert_has "$label" "$file" 'exit 1'
  # -print -quit bounds the guard's own output to one path, and the failure
  # branch prints a fixed message rather than the offending asset's contents.
  assert_has "$label" "$file" '-print -quit'
  assert_has "$label" "$file" 'Refusing to publish sensitive/config assets'
  # The broken single-job fixture intentionally omits the consumer-side name;
  # only the repaired handoff is required to pin it.
  if [[ $label == fixed ]]; then
    assert_has "$label" "$file" 'artifact_name: github-pages'
  fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The broken fixture is run 44838727519: upload and deploy in one job, no
# needs, no explicit artifact name on the consuming side.
cat > "$work/broken.yml" <<'YAML'
on: push
jobs:
  deploy:
    if: github.event_name != 'pull_request'
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
      - uses: actions/setup-node@1234567890abcdef1234567890abcdef12345678
        with:
          node-version: '20'
      - run: npm ci
        working-directory: website
      - run: npm run typecheck
        working-directory: website
      - run: npm run build
        working-directory: website
      - name: Guard Pages artifact against sensitive assets
        run: |
          set +e
          findings=$(find build -type f \( -iname '*.yaml' -o -iname '*.yml' -o -iname '*.env' -o -iname '.env.*' -o -iname '*.pem' -o -iname '*.key' -o -iname '*.toml' -o -iname '*.sql' \) -print -quit)
          status=$?
          if [[ $status -eq 0 && -n $findings ]]; then
            echo "Refusing to publish sensitive/config assets"
            exit 1
          fi
      - uses: actions/configure-pages@1234567890abcdef1234567890abcdef12345678
      - uses: actions/upload-pages-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: github-pages
          path: website/build
      - uses: actions/deploy-pages@1234567890abcdef1234567890abcdef12345678
YAML

# The fixed fixture is the repair owners must apply to the protected workflow:
# a build job that owns the guard and upload, and a deploy job that waits.
cat > "$work/fixed.yml" <<'YAML'
on:
  push:
    branches: [main]
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
      - uses: actions/setup-node@1234567890abcdef1234567890abcdef12345678
        with:
          node-version: '20'
      - run: npm ci
        working-directory: website
      - run: npm run typecheck
        working-directory: website
      - run: npm run build
        working-directory: website
      - name: Guard Pages artifact against sensitive assets
        run: |
          set +e
          findings=$(find build -type f \( -iname '*.yaml' -o -iname '*.yml' -o -iname '*.env' -o -iname '.env.*' -o -iname '*.pem' -o -iname '*.key' -o -iname '*.toml' -o -iname '*.sql' \) -print -quit)
          status=$?
          if [[ $status -eq 0 && -n $findings ]]; then
            echo "Refusing to publish sensitive/config assets"
            exit 1
          fi
      - uses: actions/configure-pages@1234567890abcdef1234567890abcdef12345678
      - uses: actions/upload-pages-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: github-pages
          path: website/build
  deploy:
    needs: build
    if: github.event_name != 'pull_request'
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/configure-pages@1234567890abcdef1234567890abcdef12345678
      - id: deployment
        uses: actions/deploy-pages@1234567890abcdef1234567890abcdef12345678
        with:
          artifact_name: github-pages
YAML

if fixed_layout "$work/broken.yml"; then
  bad 'broken fixture: single-job upload/deploy must be rejected'
else
  ok
fi
if fixed_layout "$work/fixed.yml"; then
  ok
else
  bad 'fixed fixture: two-job handoff must be accepted'
fi

# The fixed fixture is the full contract. The broken one fails the handoff but
# still has to keep every guard, so check_contract is applied to it too: a
# change that weakens the denylist cannot hide behind an already-known layout
# failure.
check_contract 'fixed' "$work/fixed.yml"
check_contract 'broken' "$work/broken.yml"

# No real-workflow grading here: the protected workflow is repaired by an
# owner as a separate handoff, and this gate must stay green until then.

printf 'pages artifact-handoff: %s passed, %s failed\n' "$pass" "$failed"
if (( failed > 0 )); then exit 1; fi
