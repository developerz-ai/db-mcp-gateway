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
  mkdir -p "$work/repo"/{bin,tests/bin,website/node_modules/.bin,.github/workflows} "$work/tools"
  cp bin/{ci,check,lint,test,check-scrub-features} "$work/repo/bin/"
  # Replace only the recursive test entry in the fixture, not the gate itself.
  printf 'echo orchestration >> "$CALLS"\n' > "$work/repo/tests/bin/check.test.sh"
  # The real token-regex regression, verbatim: the gate must run the same
  # script CI runs, so the fixture copies it instead of stubbing it.
  cp tests/bin/secret-scan-regex.test.sh "$work/repo/tests/bin/"
  # The doc-anchor guard, verbatim, for the same reason: the gate invokes
  # it, so the fixture must be able to resolve it. The fixture repo has no
  # website/docs tree, and the guard passes on a missing tree — which is
  # what lets the happy path below reach a verdict.
  cp tests/bin/doc-anchors.test.sh "$work/repo/tests/bin/"
  # One pinned ref and one local action: both halves of the SHA-pin scan's
  # filtering must accept them, or the clean run below fails.
  cat > "$work/repo/.github/workflows/ci.yml" <<'WORKFLOW'
jobs:
  fmt:
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678 # v5
      - uses: ./.github/actions/local-step # local action
WORKFLOW
  touch "$work/repo/website/node_modules/.bin/"{tsc,docusaurus}
  chmod +x "$work/repo/website/node_modules/.bin/"*
  # Only what the gate still resolves on this PATH: the scripts' dirname, the
  # interpreter, grep (a bin/check REQUIRED probe, the SHA-pin scan's matcher
  # and check-scrub-features'), find (the Pages guard and the anchor guard's
  # doc walk), tr (the token-regex regression's hex helper), and the anchor
  # guard's locale probe plus its sed/sort helpers (the sed is the guard's
  # doc-discovery pipeline; the discovery-failure case below swaps in a
  # failing stub). basename is the anchor guard's cross-file link resolver.
  # mkdir/rm/touch are the external commands the stub itself runs.
  for tool in bash dirname basename grep find mkdir rm touch tr locale sed sort; do
    ln -s "$(command -v "$tool")" "$work/tools/$tool"
  done
  cat > "$work/tools/stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$CALLS"
case "$name $*" in
  'node -e '*) exit "${NODE_RC:-0}" ;;
  'git grep '*)
    # rc=0 with a match line fails the gate; any rc other than 1 fails it
    # closed; only the default rc=1 (no match) reads as clean. The simulated
    # token deliberately cannot match the real guard regex; the multi-token
    # fixture's filename tokens can — exercising their redaction is the point.
    if [[ -n ${TOKEN_HIT_MULTI:-} ]]; then
      echo "config/${TOKEN_A}_and_${TOKEN_B}.yaml:3: dbmcp_svc_SIMULATED_TOKEN_FIXTURE_ONLY_NOT_HEX"
      exit 0
    fi
    if [[ -n ${TOKEN_HIT:-} ]]; then
      echo 'config/prod.yaml:9: dbmcp_svc_SIMULATED_TOKEN_FIXTURE_ONLY_NOT_HEX'
      exit 0
    fi
    exit "${GIT_GREP_RC:-1}" ;;
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
  'cargo test '*|'cargo nextest '*)
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
  for tool in cargo cargo-audit docker node npm rustc cc make git; do
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
# A matched token must never reach the gate's output: the hit IS the
# credential, and the gate's output is copied into PRs. The needles are not
# echoed, so a failure never copies a token into the test log either.
assert_no_token_in_output() {
  local tok
  for tok in "$@"; do
    if grep -qF -- "$tok" "$work/output"; then
      echo 'FAIL: the gate output contains the matched token'
      exit 1
    fi
  done
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

# Two DIFFERENT simulated 64-hex tokens for the multi-token filename fixture:
# one repeated hex character each, so they cannot be mistaken for real ones.
token_a="dbmcp_svc_$(printf 'a%.0s' {1..64})"
token_b="dbmcp_svc_$(printf 'b%.0s' {1..64})"

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
  'git grep -nE dbmcp_svc_[0-9a-f]{64} -- :!tests/** :!website/** :!config/example.yaml :!.github/** :!src/config/yaml/**' \
  'npm run typecheck' 'npm run build' 'orchestration'; do
  called "$call"
done
# The tracked-token scan's exact command line is pinned in the loop above
# (git is stubbed, so the call is recorded). The SHA-pin scan's greps are the
# REAL grep and leave no call trace, so their verdicts are the pin: the happy
# path passes with a pinned ref and a local action in the fixture workflow,
# and the unpinned case below fails on a mutable tag.
assert_output 'no literal service tokens in committed config (git grep rc=1)'
# The token-regex regression ran the real script copied into the fixture.
assert_output 'passed, 0 failed'
# The doc-anchor guard ran too: the gate invokes it, so the fixture must
# prove the wiring, not just that the script was copied.
assert_output 'no website/docs tree — nothing to check (pass)'
# Every job ran: the summary must claim no skip.
assert_output '✓ Local quality checks passed (no publishing or deployment)'
not_called 'ps --status running'
# Readiness is rechecked even for an already-started stack; quoted args survive.
rm "$work/calls.ready"
(cd "$work/repo" && PATH="$work/tools" CALLS="$work/calls" EXPECT_FILTER='filter with spaces' \
  bash bin/test --test smoke -- --nocapture 'filter with spaces')
called 'cargo test --all-targets --all-features --test smoke -- --nocapture filter with spaces'
# With cargo-nextest installed bin/test runs it instead, args intact.
rm "$work/calls.ready"
ln -s stub "$work/tools/cargo-nextest"
(cd "$work/repo" && PATH="$work/tools" CALLS="$work/calls" EXPECT_FILTER='filter with spaces' \
  bash bin/test --test smoke -- --nocapture 'filter with spaces')
called 'cargo nextest run --all-targets --all-features --test smoke -- --nocapture filter with spaces'
rm "$work/tools/cargo-nextest"
# The restored ci.yml parity stages, exercised against the real scan code: a
# mutable action ref fails the SHA-pin scan, a committed token fails the
# tracked-token scan, and a git grep that cannot run fails closed (#190).
fixture
printf 'jobs:\n  fmt:\n    steps:\n      - uses: actions/checkout@v5\n' \
  > "$work/repo/.github/workflows/ci.yml"
run_gate 1
assert_output 'unpinned action ref(s)'
assert_not_run "NOT RUN: secret-scan - the gate stopped before this job"

# A SHA-pin scan that cannot read its input fails closed. As one pipeline the
# first grep exited 2 (no .github/workflows) while the downstream filters
# exited 1, and pipefail reported the clean 1 — a missing workflows directory
# read as a clean scan.
fixture
rm -rf "$work/repo/.github/workflows"
run_gate 1
assert_output 'grep tooling failure (rc=2) — SHA-pin scan cannot read as clean (fail-closed)'
assert_not_run "NOT RUN: test - the gate stopped before this job"

fixture
run_gate 1 TOKEN_HIT=1
assert_output 'literal dbmcp_svc_ service token(s) in committed config'
# The hit IS the credential: the gate reports where it is, never what it is.
assert_output 'config/prod.yaml:9'
assert_no_token_in_output 'dbmcp_svc_SIMULATED_TOKEN_FIXTURE_ONLY_NOT_HEX'
assert_not_run "NOT RUN: pages typecheck/build/artifact guard - the gate stopped before this job"

# A filename can carry the token itself — here two DIFFERENT tokens, and both
# must be masked: a single match+replace left the second one in the output.
fixture
run_gate 1 TOKEN_HIT_MULTI=1 TOKEN_A="$token_a" TOKEN_B="$token_b"
assert_output 'literal dbmcp_svc_ service token(s) in committed config'
assert_output 'config/<redacted>_and_<redacted>.yaml:3'
assert_no_token_in_output "$token_a" "$token_b" 'dbmcp_svc_SIMULATED_TOKEN_FIXTURE_ONLY_NOT_HEX'
assert_not_run "NOT RUN: pages typecheck/build/artifact guard - the gate stopped before this job"

fixture
run_gate 1 GIT_GREP_RC=128
assert_output 'git grep tooling failure (rc=128) — secret-scan cannot read as clean (fail-closed, #190)'
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
# A job the gate never reached is named, never silently dropped: each pending
# job's notice appears where the gate stopped AND in the final list.
fixture
run_gate 42 FAIL_AT='cargo fmt --all -- --check'
assert_output 'Jobs not reached'
for job in 'test' 'cargo audit' 'secret-scan' 'doc-anchor guard' 'pages typecheck/build/artifact guard'; do
  assert_not_run "NOT RUN: $job - the gate stopped before this job"
done

# REQUIRED prerequisites: absent -> 75, the gate cannot grade. The refusal
# lives in exactly one place — bin/check's preflight — so the loop covers
# exactly the tools it probes, except bash: the harness itself resolves the
# gate's interpreter through this fixture's PATH.
for missing in cargo rustc cc make docker grep; do
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
# The token-regex regression ran too; bash itself is not stubbed, so its
# output is the proof it executed.
assert_output 'passed, 0 failed'

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

# A Pages build that leaves no build directory is refused, not passed.
fixture
run_gate 1 NO_BUILD_DIR=1
assert_output 'Website build directory missing'
for asset in config.yaml config.YML secret.env .env.local cert.pem cert.key config.toml dump.sql; do
  fixture
  run_gate 1 ASSET="$asset"
done
fixture
printf '#!/usr/bin/env bash\nexit 45\n' > "$work/tools/broken-find"
chmod +x "$work/tools/broken-find"
rm "$work/tools/find"
ln -s broken-find "$work/tools/find"
run_gate 45
fixture
printf 'exit 44\n' > "$work/repo/tests/bin/check.test.sh"
run_gate 44
# Stopping at the FIRST job names every job the gate never reached.
for job in 'fmt + clippy' 'test' 'cargo audit' 'secret-scan' 'doc-anchor guard' 'pages typecheck/build/artifact guard'; do
  assert_not_run "NOT RUN: $job - the gate stopped before this job"
done
# A VALID fragment resolves and the gate passes. The double-hyphen target is
# the acceptance-critical one: "### MySQL / MSSQL — deferred" renders as
# "mysql--mssql--deferred", because the slash and the em dash are DELETED
# and each of the two spaces around them becomes its own hyphen — a
# whitespace RUN is not collapsed into one. The all-ASCII "Two  spaces"
# heading pins the same rule on the slugger's fast path, where the run is a
# literal "  " rather than two spaces made adjacent by a deletion.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Real heading\n\n### MySQL / MSSQL — deferred\n\n## Two  spaces\n\nSee [below](#real-heading), [deferred](#mysql--mssql--deferred) and [two](#two--spaces).\n' \
  > "$work/repo/website/docs/valid.md"
printf '# Title\n\n## Other heading\n' > "$work/repo/website/docs/other.md"
printf '# Title\n\n## Cross-file heading\n\nSee [across](./other.md#other-heading).\n' \
  > "$work/repo/website/docs/cross.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# A broken heading FRAGMENT fails the gate. The Docusaurus build only
# WARNS about a broken anchor (onBrokenAnchors defaults to 'warn'), so the
# anchor guard is the thing that makes it fail — and the gate must fail on
# it.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Real heading\n\nSee [below](#no-such-heading).\n' \
  > "$work/repo/website/docs/broken.md"
run_gate 1
assert_output 'resolves to no heading in'
# A broken CROSS-FILE fragment fails the gate too. The guard resolves the
# link's path against the doc tree, so a fragment that matches no heading
# in the OTHER file is caught — and a guard that skipped cross-file
# resolution would read this case as clean and let the gate pass.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Other heading\n' > "$work/repo/website/docs/other.md"
printf '# Title\n\n## Cross-file heading\n\nSee [across](./other.md#no-such-heading).\n' \
  > "$work/repo/website/docs/cross-broken.md"
run_gate 1
assert_output 'resolves to no heading in'
# The page TITLE is not an anchor: Docusaurus renders the level-1 heading
# without an id, so the guard skips it — if that skip is deleted, `title`
# becomes an ID, this link resolves and the gate wrongly passes. The real
# heading in the same file shows the failure is about the h1, not an empty
# inventory.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Real heading\n\nSee [top](#title).\n' \
  > "$work/repo/website/docs/h1.md"
run_gate 1
assert_output 'resolves to no heading in'
# A heading inside a FENCED code block is not a heading either: the fence
# skip keeps it out of the ID inventory. The fenced line is deliberately
# level 2 — a level-1 line would also be dropped by the h1 skip above, so
# deleting only the fence skip could never flip this verdict. With the
# fence skip deleted, `fake-heading` is inventoried, the link resolves and
# the gate wrongly passes.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n```sh\n## fake heading\n```\n\nSee [fake](#fake-heading).\n' \
  > "$work/repo/website/docs/fenced.md"
run_gate 1
assert_output 'resolves to no heading in'
# A fence is tracked by CHARACTER and LENGTH: inside a four-backtick block a
# three-backtick example is CONTENT, not a closer, so the ## fake line stays
# hidden and #fake must fail — while ## Real heading after the matching
# four-backtick closer is still found. With length-blind toggling the inner
# fence opened and closed the block, the fake heading was inventoried and
# the dead #fake link passed.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n````md\n```sh\n## fake heading\n```\n````\n\n## Real heading\n\nSee [fake](#fake-heading) and [real](#real-heading).\n' \
  > "$work/repo/website/docs/fence-nested.md"
run_gate 1
assert_output 'resolves to no heading in'
# An HTML comment hides its whole contents: the commented-out heading is
# not an anchor, so #hidden-heading fails…
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n<!--\n## Hidden heading\n-->\n\n## Real heading\n\nSee [hidden](#hidden-heading) and [real](#real-heading).\n' \
  > "$work/repo/website/docs/commented-heading.md"
run_gate 1
assert_output 'resolves to no heading in'
# …and a commented-out LINK is not a link either: the doc's only dead
# fragment link sits inside the comment and must not fail the guard.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n<!-- [old](#no-such-heading) -->\n\n## Real heading\n\nSee [real](#real-heading).\n' \
  > "$work/repo/website/docs/commented-link.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# An explicit {#id} renders verbatim instead of a slug of the whole heading
# text: #custom-id resolves…
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Heading {#custom-id}\n\nSee [direct](#custom-id).\n' \
  > "$work/repo/website/docs/explicit-id.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# …and the invented whole-string slug no longer exists.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Heading {#custom-id}\n\nSee [invented](#heading-custom-id).\n' \
  > "$work/repo/website/docs/explicit-id-broken.md"
run_gate 1
assert_output 'resolves to no heading in'
# github-slugger reserves every id it emits: A, A-1, A render a, a-1 and
# a-2 — the second A climbs past the a-1 the literal heading emitted, so
# the valid #a-2 link resolves. Counter-collision produced a, a-1, a-1 and
# rejected the real #a-2.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## A\n\n## A-1\n\n## A\n\nSee [a](#a), [a1](#a-1) and [a2](#a-2).\n' \
  > "$work/repo/website/docs/dedupe.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# Lowercase is JavaScript's, not bash's: a final sigma (a capital Σ after a
# cased character with none following) is ς, so ## ΟΣ renders ος and
# ## ΟΣ ΑΣ renders ος-ας — both links resolve…
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## ΟΣ\n\n## ΟΣ ΑΣ\n\n## ΑΣ\n\nSee [x](#ος), [y](#ος-ας) and [z](#ας).\n' \
  > "$work/repo/website/docs/sigma.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# …and the plain-form σ the bash lowercasing would have produced is a dead
# anchor and fails.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## ΟΣ\n\nSee [x](#οσ).\n' > "$work/repo/website/docs/sigma-broken.md"
run_gate 1
assert_output 'resolves to no heading in'
# A backslash inside a heading's code span is deleted like any other
# punctuation: `a\b` renders ab. The ASCII fast path must delete ONE
# backslash — its '\\' list entry held two, so a single one survived and
# the slug kept it.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## The `a\\b` switch\n\nSee [x](#the-ab-switch).\n' \
  > "$work/repo/website/docs/backslash.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# Link NODES are parsed, not raw ]( lines: a [x](#missing) inside an inline
# code span is literal text, and an optional title is link syntax — the
# titled, single-quoted and angle forms all resolve to #real-heading.
fixture
mkdir -p "$work/repo/website/docs"
cat > "$work/repo/website/docs/link-nodes.md" <<'DOC'
# Title

## Real heading

Code `[x](#missing)` is text. Titled [x](#real-heading "title"),
single [y](#real-heading 'title') and angled [z](<#real-heading>).
DOC
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# An EXTENSIONLESS page URL renders from its markdown source: ./other is
# other.md, so a dead fragment behind the valid page URL fails instead of
# being skipped as an unknown file (the old FILE_SEEN lookup dropped it
# silently — and dropped the VALID extensionless link with it).
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Other heading\n' > "$work/repo/website/docs/other.md"
printf '# Title\n\n## Cross-file heading\n\nSee [ok](./other#other-heading) and [dead](./other#no-such-heading).\n' \
  > "$work/repo/website/docs/cross-ext.md"
run_gate 1
assert_output 'resolves to no heading in'
# The trailing-slash form renders the directory's index page, and a valid
# fragment behind it resolves rather than being skipped or failing.
fixture
mkdir -p "$work/repo/website/docs/sub"
printf '# Title\n\n## Sub heading\n' > "$work/repo/website/docs/sub/index.md"
printf '# Title\n\n## Here\n\nSee [idx](./sub/#sub-heading).\n' \
  > "$work/repo/website/docs/index-link.md"
run_gate 0
assert_output 'every heading fragment link resolves to a rendered heading ID'
# Discovery failing must fail the guard, not grade a partial inventory: as
# a process substitution the discovery pipeline's exit status was lost, so
# a failing sed read as an empty doc list and every link passed. The docs
# tree EXISTS here, so the guard actually reaches discovery.
fixture
mkdir -p "$work/repo/website/docs"
printf '# Title\n\n## Real heading\n\nSee [x](#real-heading).\n' \
  > "$work/repo/website/docs/valid.md"
printf '#!/usr/bin/env bash\nexit 45\n' > "$work/tools/broken-sed"
chmod +x "$work/tools/broken-sed"
rm "$work/tools/sed"
ln -s broken-sed "$work/tools/sed"
run_gate 1
assert_output 'website/docs discovery failed'
assert_not_run "NOT RUN: pages typecheck/build/artifact guard - the gate stopped before this job"
printf 'check orchestration regressions passed\n'
