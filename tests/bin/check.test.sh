#!/usr/bin/env bash
# Isolated orchestration tests; no real database or toolchain is invoked.
#
# The gate has two kinds of missing prerequisite, and this file pins both:
#   REQUIRED     absent -> exit 75 (the gate cannot grade anything)
#   GATE-SCOPED  absent -> that one job is reported 'NOT RUN', the gate keeps
#                grading the rest and still reaches a verdict (exit 0).
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fixture() {
  rm -rf "$work/repo" "$work/tools" "$work/calls.ready"
  mkdir -p "$work/repo"/{bin,tests/bin,.github/workflows,website/node_modules/.bin} "$work/tools"
  cp bin/{ci,check,lint,test,check-scrub-features} "$work/repo/bin/"
  cp tests/bin/secret-scan-regex.test.sh "$work/repo/tests/bin/"
  # Replace only the recursive test entry in the fixture, not the gate itself.
  printf 'echo orchestration >> "$CALLS"\n' > "$work/repo/tests/bin/check.test.sh"
  printf '%s\n' '- uses: owner/action@0123456789abcdef0123456789abcdef01234567 # v1' > "$work/repo/.github/workflows/ci.yml"
  touch "$work/repo/website/node_modules/.bin/"{tsc,docusaurus}
  chmod +x "$work/repo/website/node_modules/.bin/"*
  for tool in bash dirname grep find tr mkdir touch mktemp cp chmod rm ln; do
    ln -s "$(command -v "$tool")" "$work/tools/$tool"
  done
  cat > "$work/tools/stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$CALLS"
case "$name $*" in
  'node -e '*) exit "${NODE_RC:-0}" ;;
  'git rev-parse '*) exit 0 ;;
  'git grep '*)
    # Even tooling errors may contain secrets; none may escape the gate.
    if [[ ${SCAN_RC:-1} != 1 ]]; then
      printf '%s\n' 'PRIVATE_TOKEN_DIAGNOSTIC' >&2
    fi
    exit "${SCAN_RC:-1}" ;;
  'docker compose '*ps*)
    # Realistic service/state/health fields: 'running' alone is discarded by
    # the health check, so the fixture would prove nothing about it.
    printf '%s\n' 'state-db running unhealthy' 'target-db running healthy' ;;
  'docker compose '*config*)
    # A malformed compose file is a configuration fault, not an environment one.
    exit "${COMPOSE_CONFIG_RC:-0}" ;;
  'docker compose -f docker-compose.dev.yml up -d --wait')
    [[ "$name $*" != "${FAIL_AT:-}" ]] || exit 42
    touch "$CALLS.ready" ;;
  'cargo test '*)
    # A running state DB is deliberately insufficient in this fixture.
    [[ -f $CALLS.ready ]] || { echo 'FAIL: cargo before full-stack readiness'; exit 46; }
    if [[ -n ${EXPECT_FILTER:-} ]]; then
      [[ ${!#} == "$EXPECT_FILTER" ]] || exit 47
    fi ;;
  'cargo tree '*)
    printf 'regex-syntax feature "unicode-case"\nregex-syntax feature "unicode-perl"\n' ;;
  'npm run build')
    # A build that reports success without leaving a build directory must
    # still be refused by the gate's artifact guard.
    if [[ -n ${NO_BUILD_DIR:-} ]]; then rm -rf build; exit 0; fi
    mkdir -p build
    [[ -z ${ASSET:-} ]] || touch "build/$ASSET" ;;
esac
if [[ "$name $*" == "${FAIL_AT:-}" ]]; then exit 42; fi
STUB
  chmod +x "$work/tools/stub"
  # bin/check preflights the host toolchain before the gate runs, so rustc, cc
  # and make have to resolve on PATH exactly like cargo and docker do.
  for tool in cargo cargo-audit docker node npm git rustc cc make; do
    ln -s stub "$work/tools/$tool"
  done
  : > "$work/calls"
}

run_gate() {
  local expected=$1 rc=0
  shift
  (cd "$work/repo" && env PATH="$work/tools" HOME="$work" CALLS="$work/calls" "$@" bash bin/check) > "$work/output" 2>&1 || rc=$?
  if [[ $rc != "$expected" ]]; then
    printf 'FAIL: expected exit %s, got %s\n' "$expected" "$rc"
    # Output is fixture-only, but avoid printing simulated token diagnostics.
    exit 1
  fi
}
called() { grep -qF -- "$1" "$work/calls"; }
not_called() { if called "$1"; then echo "FAIL: unexpected call $1"; exit 1; fi; }
assert_output() {
  if ! grep -qF -- "$1" "$work/output"; then
    printf 'FAIL: expected output to contain: %s\n' "$1"
    exit 1
  fi
}
not_output() {
  if grep -qF -- "$1" "$work/output"; then
    printf 'FAIL: expected output NOT to contain: %s\n' "$1"
    exit 1
  fi
}
# The final summary must repeat every skipped job's notice. Asserting over the
# whole output would also pass on the initial notice alone, so the assertion is
# scoped to the summary section.
assert_summary() {
  local needle=$1 section
  section=$(grep -A 40 \
    '^Jobs not run (their toolchain is absent; every other job was graded):$' \
    "$work/output" || true)
  if ! grep -qF -- "$needle" <<<"$section"; then
    printf 'FAIL: final summary does not contain: %s\n' "$needle"
    exit 1
  fi
}
# A job the gate never reached gets the required notice, and the notice is
# repeated in the final list of jobs that never ran.
assert_not_run() {
  local needle=$1 count
  count=$(grep -cF -- "$needle" "$work/output" || true)
  if (( count < 2 )); then
    printf 'FAIL: expected the not-run notice twice (notice + final list), got %s: %s\n' \
      "$count" "$needle"
    exit 1
  fi
}

fixture
run_gate 0
for call in \
  'cargo fmt --all -- --check' \
  'cargo clippy --all-targets --all-features -- -D warnings' \
  'cargo clippy --release --all-features -- -D warnings' \
  'cargo tree -e features -i regex-syntax -e no-dev' \
  'docker compose -f docker-compose.dev.yml up -d --wait' \
  'cargo test --all-targets --all-features' \
  'cargo audit --ignore RUSTSEC-2023-0071' \
  'npm run typecheck' 'npm run build' 'orchestration' \
  'git grep -qE dbmcp_svc_[0-9a-f]{64} -- :!tests/** :!website/** :!config/example.yaml :!.github/** :!src/config/yaml.rs'; do
  called "$call"
done
# Every job ran: the summary must claim no skip.
assert_output '✓ Local quality checks passed (no publishing or deployment)'
not_called 'ps --status running'
# Readiness is rechecked even for an already-started stack; quoted args survive.
rm "$work/calls.ready"
(cd "$work/repo" && PATH="$work/tools" CALLS="$work/calls" EXPECT_FILTER='filter with spaces' \
  bash bin/test --test smoke -- --nocapture 'filter with spaces')
called 'cargo test --all-targets --all-features --test smoke -- --nocapture filter with spaces'
fixture
run_gate 75 FAIL_AT='docker compose -f docker-compose.dev.yml up -d --wait'
not_called 'cargo test --all-targets --all-features'
not_called 'cargo audit --ignore RUSTSEC-2023-0071'
# The 75 names the unreachable resource instead of one generic message.
assert_output 'Required prerequisite unavailable: dev stack'
# The per-service diagnostics are part of the report: the unhealthy service is
# named with its health, and a healthy service is not listed.
assert_output 'state-db (health: unhealthy)'
not_output 'target-db'
# A malformed compose file is a broken change, not an unreachable resource: its
# own status is preserved, so the platform blames the change and not the box.
fixture
rc=0
(cd "$work/repo" && PATH="$work/tools" CALLS="$work/calls" \
  FAIL_AT='docker compose -f docker-compose.dev.yml up -d --wait' COMPOSE_CONFIG_RC=1 \
  bash bin/test) > "$work/output" 2>&1 || rc=$?
[[ $rc == 1 ]] || { echo "FAIL: a malformed compose file must keep its own status, got $rc"; exit 1; }
assert_output 'docker compose configuration is invalid'
not_called 'cargo test --all-targets --all-features'
# Direct bin/test must also classify unavailable Docker as setup failure.
fixture
rm "$work/tools/docker"
rc=0
(cd "$work/repo" && PATH="$work/tools" CALLS="$work/calls" bash bin/test) > "$work/output" 2>&1 || rc=$?
[[ $rc == 75 ]] || { echo 'FAIL: missing Docker must return 75'; exit 1; }
assert_output 'Required prerequisite unavailable: Docker CLI'
not_called 'cargo test --all-targets --all-features'
# The remaining Docker probes name their own unreachable resource.
for probe in 'docker info:Docker daemon' \
  'docker compose -f docker-compose.dev.yml version:Docker Compose'; do
  fixture
  rc=0
  (cd "$work/repo" && PATH="$work/tools" CALLS="$work/calls" FAIL_AT="${probe%%:*}" bash bin/test) \
    > "$work/output" 2>&1 || rc=$?
  [[ $rc == 75 ]] || { echo "FAIL: ${probe##*:} must return 75"; exit 1; }
  assert_output "Required prerequisite unavailable: ${probe##*:}"
  not_called 'cargo test --all-targets --all-features'
done

for stage in 'cargo fmt --all -- --check' \
  'cargo clippy --all-targets --all-features -- -D warnings' \
  'cargo clippy --release --all-features -- -D warnings' \
  'cargo tree -e features -i regex-syntax -e no-dev' \
  'cargo test --all-targets --all-features' \
  'cargo audit --ignore RUSTSEC-2023-0071' 'npm run typecheck' 'npm run build'; do
  fixture
  run_gate 42 FAIL_AT="$stage"
  if [[ $stage != 'npm run build' ]]; then not_called 'npm run build'; fi
done
# A job the gate never reached is named, never silently dropped.
fixture
run_gate 42 FAIL_AT='cargo fmt --all -- --check'
assert_output 'Jobs not reached'
assert_output 'pages typecheck/build/artifact guard'

# REQUIRED prerequisites: absent -> 75, the gate cannot grade.
# Every tool bin/check's preflight or bin/ci requires, except bash: the
# harness itself resolves the gate's interpreter through this fixture's PATH.
for missing in cargo rustc cc make docker git grep find \
  tr mktemp cp chmod rm ln mkdir touch; do
  fixture
  rm "$work/tools/$missing"
  run_gate 75
  not_called 'cargo audit --ignore RUSTSEC-2023-0071'
done
for prerequisite in 'cargo fmt --version' 'cargo clippy --version' \
  'docker compose version' 'docker info'; do
  fixture
  run_gate 75 FAIL_AT="$prerequisite"
done

# GATE-SCOPED toolchains: absent -> that job is NOT RUN, the gate still grades.
fixture
rm "$work/tools/cargo-audit"
run_gate 0
not_called 'cargo audit --ignore RUSTSEC-2023-0071'
assert_output 'NOT RUN: cargo audit - cargo-audit is not on PATH (install: cargo install cargo-audit)'
assert_output 'Jobs not run'
assert_summary 'NOT RUN: cargo audit - cargo-audit is not on PATH (install: cargo install cargo-audit)'
assert_output '✓ Local quality checks passed for the gates that ran (no publishing or deployment)'
# The rest of the gate still ran.
called 'cargo test --all-targets --all-features'
called 'npm run typecheck'

fixture
rm "$work/tools/node"
run_gate 0
not_called 'npm run typecheck'
not_called 'npm run build'
assert_output 'NOT RUN: pages typecheck/build/artifact guard - Node 20+ is not on PATH'
assert_summary 'NOT RUN: pages typecheck/build/artifact guard - Node 20+ is not on PATH'
called 'cargo test --all-targets --all-features'

fixture
rm "$work/tools/npm"
run_gate 0
not_called 'npm run typecheck'
not_called 'npm run build'
assert_output 'NOT RUN: pages typecheck/build/artifact guard - npm is not on PATH'
assert_summary 'NOT RUN: pages typecheck/build/artifact guard - npm is not on PATH'
called 'cargo audit --ignore RUSTSEC-2023-0071'

for dependency in tsc docusaurus; do
  fixture
  rm -f "$work/repo/website/node_modules/.bin/$dependency"
  run_gate 0
  not_called 'npm run typecheck'
  not_called 'npm run build'
  assert_output 'NOT RUN: pages typecheck/build/artifact guard - website dependencies are absent (prepare: cd website && npm ci)'
  assert_summary 'NOT RUN: pages typecheck/build/artifact guard - website dependencies are absent (prepare: cd website && npm ci)'
done

fixture
run_gate 0 NODE_RC=1
not_called 'npm run typecheck'
not_called 'npm run build'
assert_output 'NOT RUN: pages typecheck/build/artifact guard - an older Node than 20 is on PATH'
assert_summary 'NOT RUN: pages typecheck/build/artifact guard - an older Node than 20 is on PATH'

for rc in 0 2 128; do
  fixture
  run_gate 1 SCAN_RC="$rc"
  not_called 'cargo fmt --all -- --check'
  if grep -qF PRIVATE_TOKEN_DIAGNOSTIC "$work/output"; then
    echo 'FAIL: token diagnostics leaked'; exit 1
  fi
done
# No uses, local-only uses, and mixed local/remote workflows all remain valid.
for actions in none local mixed; do
  fixture
  case "$actions" in
    none) printf 'name: no actions\n' > "$work/repo/.github/workflows/ci.yml" ;;
    local) printf '%s\n' '- uses: ./local-action' > "$work/repo/.github/workflows/ci.yml" ;;
    mixed) printf '%s\n' '- uses: ./local-action' >> "$work/repo/.github/workflows/ci.yml" ;;
  esac
  run_gate 0
done
fixture
printf '%s\n' '- uses: ./local-action' '- uses: owner/action@v1' > "$work/repo/.github/workflows/new.yaml"
run_gate 1
not_called 'cargo fmt --all -- --check'
# The gate stopped at the SHA-pin scan: every job it never reached is named
# with the required notice and repeated in the final list.
assert_output 'Jobs not reached'
for job in 'secret-scan (tracked service-token scan)' 'secret-scan regex regression' \
  'orchestration regression' 'fmt + clippy' 'test' 'cargo audit' \
  'pages typecheck/build/artifact guard'; do
  assert_not_run "NOT RUN: $job - the gate stopped before this job"
done
fixture
# A grep failure must not be converted to an empty/clean pin scan.
printf '#!/usr/bin/env bash\nexit 2\n' > "$work/tools/broken-grep"
chmod +x "$work/tools/broken-grep"
rm "$work/tools/grep"
ln -s broken-grep "$work/tools/grep"
run_gate 75
# Fail each pin-scan stage after the PCRE capability probe succeeds.
for pattern in '^\s*-?\s*uses:\s*' '^\s*-?\s*uses:\s*\./' \
  '^\s*-?\s*uses:\s*[^[:space:]#]+@[0-9a-f]{40}\s+#\s+\S+\s*$'; do
  fixture
  printf '#!/usr/bin/env bash\nfor arg in "$@"; do\n  [[ $arg != %q ]] || exit 2\ndone\nexec %q "$@"\n' \
    "$pattern" "$(command -v grep)" > "$work/tools/scanner-grep"
  chmod +x "$work/tools/scanner-grep"
  rm "$work/tools/grep"
  ln -s scanner-grep "$work/tools/grep"
  run_gate 1
  not_called 'cargo fmt --all -- --check'
done
fixture
printf '#!/usr/bin/env bash\nexit 45\n' > "$work/tools/broken-find"
chmod +x "$work/tools/broken-find"
rm "$work/tools/find"
ln -s broken-find "$work/tools/find"
run_gate 45
# A Pages build that leaves no build directory is refused, not passed.
fixture
run_gate 1 NO_BUILD_DIR=1
assert_output 'Website build directory missing'
for asset in config.yaml config.YML secret.env .env.local cert.pem cert.key config.toml dump.sql; do
  fixture
  run_gate 1 ASSET="$asset"
done
fixture
printf 'exit 43\n' > "$work/repo/tests/bin/secret-scan-regex.test.sh"
run_gate 43
fixture
printf 'exit 44\n' > "$work/repo/tests/bin/check.test.sh"
run_gate 44
printf 'check orchestration regressions passed\n'
