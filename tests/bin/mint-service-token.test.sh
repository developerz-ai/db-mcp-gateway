#!/usr/bin/env bash
# tests/bin/mint-service-token.test.sh — acceptance test for bin/mint-service-token
# (spec 14). Self-contained shell test: invokes the script with several inputs
# and asserts the contract documented at the top of bin/mint-service-token.
#
# Run:
#   bash tests/bin/mint-service-token.test.sh
#
# Exits 0 on success, 1 on the first failed assertion. The script itself is
# invoked with `set -euo pipefail` inside, but each assertion prints the
# failing input and what was expected so a CI failure is debuggable.
#
# Requires:
#   - bash >= 4 (uses [[ ... =~ ... ]])
#   - openssl (the script calls `openssl rand -hex 32` to generate the token)
#   - grep with -E (POSIX-extended regex)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/bin/mint-service-token"

if [[ ! -x "$SCRIPT" ]]; then
  echo "FAIL: $SCRIPT not found or not executable" >&2
  exit 1
fi

# Counters — printed at the end so a green run is auditable.
PASS=0
FAIL=0
FAILED_ASSERTIONS=()

assert_eq() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    PASS=$((PASS + 1))
    echo "  ok  $name"
  else
    FAIL=$((FAIL + 1))
    FAILED_ASSERTIONS+=("$name (expected: <$expected>, got: <$actual>)")
    echo "  FAIL $name"
    echo "       expected: <$expected>"
    echo "       got:      <$actual>"
  fi
}

assert_match() {
  local name="$1" pattern="$2" actual="$3"
  if [[ "$actual" =~ $pattern ]]; then
    PASS=$((PASS + 1))
    echo "  ok  $name"
  else
    FAIL=$((FAIL + 1))
    FAILED_ASSERTIONS+=("$name (pattern: $pattern, got: <$actual>)")
    echo "  FAIL $name"
    echo "       pattern: $pattern"
    echo "       got:     <$actual>"
  fi
}

assert_contains() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1))
    echo "  ok  $name"
  else
    FAIL=$((FAIL + 1))
    FAILED_ASSERTIONS+=("$name (needle: <$needle>)")
    echo "  FAIL $name"
    echo "       expected to contain: <$needle>"
    echo "       got: <$haystack>"
  fi
}

assert_not_contains() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1))
    echo "  ok  $name"
  else
    FAIL=$((FAIL + 1))
    FAILED_ASSERTIONS+=("$name (must NOT contain: <$needle>)")
    echo "  FAIL $name"
    echo "       must NOT contain: <$needle>"
    echo "       got: <$haystack>"
  fi
}

# Run the script; capture stdout, stderr, and exit status into separate vars so
# each assertion can compare the right stream.
run_mint() {
  local arg="$1"
  set +e
  OUT="$( "$SCRIPT" "$arg" 2> /tmp/mint-stderr.$$ )"
  EXIT=$?
  ERR="$(cat /tmp/mint-stderr.$$)"
  rm -f /tmp/mint-stderr.$$
  set -e
}

# Extract just the YAML stanza (lines between "service_accounts:" and the
# first blank line that follows). The raw token is shown ONCE at the top of
# the output by design (operator copies it into Vaultwarden), so checking
# "raw token absent from output" is wrong — the assertion must scope to the
# YAML block only, where the secret reference is the right surface.
extract_stanza() {
  awk '/^service_accounts:/{flag=1; print; next} flag && NF==0{flag=0} flag' <<<"$1"
}

echo "=== bin/mint-service-token acceptance ==="

echo
echo "-- invalid service names (exit status 2) --"
# Empty string, uppercase, spaces, leading dash, internal underscore — all
# rejected by ^[a-z0-9][a-z0-9-]{0,62}$ at the script level.
# (Trailing-hyphen IS accepted by the script's regex — see spec 14.)
for bad in "" "Bad_Name" "UPPER" "with space" "-leading-dash" "under_score" "$(printf 'a%.0s' {1..64})"; do
  run_mint "$bad"
  assert_eq "exit status for <$bad>" "2" "$EXIT"
done

echo
echo "-- missing-arg usage (exit status 2) --"
run_mint ""
assert_contains "usage line on stderr" "usage: bin/mint-service-token <name>" "$ERR"

echo
echo "-- valid name generates the documented token pattern --"
run_mint "ci-bot"
assert_eq "exit status for ci-bot" "0" "$EXIT"
# Extract the line starting with "token (store this — shown once): " and grab
# the second whitespace-separated field — that's the token value.
TOKEN="$(grep -E '^token \(store this.*\): ' <<<"$OUT" | awk '{print $NF}')"
assert_match "token shape ci-bot" '^dbmcp_svc_[0-9a-f]{64}$' "$TOKEN"
# 10-char prefix `dbmcp_svc_` + 64 hex = 74 chars total.
assert_eq "token length 74 (10-char prefix + 64 hex)" "74" "${#TOKEN}"

echo
echo "-- ci-bot -> SERVICE_TOKEN_CI_BOT env var name --"
assert_contains "env var name ci-bot" "SERVICE_TOKEN_CI_BOT" "$OUT"
# shellcheck disable=SC2016  # literal `${ENV:…}` must not expand — we want it to match verbatim
assert_contains "env var ref in stanza ci-bot" '${ENV:SERVICE_TOKEN_CI_BOT}' "$OUT"

echo
echo "-- generated YAML stanza uses secret reference, never the token --"
STANZA="$(extract_stanza "$OUT")"
assert_contains "service_accounts stanza header" 'service_accounts:' "$STANZA"
assert_contains "name field set to ci-bot" 'name: ci-bot' "$STANZA"
assert_contains "group derived as svc-ci-bot" 'group: svc-ci-bot' "$STANZA"
# shellcheck disable=SC2016  # literal `${ENV:…}` must not expand — we want it to match verbatim
assert_contains "token field uses ENV ref" 'token: ${ENV:SERVICE_TOKEN_CI_BOT}' "$STANZA"
# CRITICAL: the YAML stanza must NOT contain the raw token. The token value
# is only meant to live in the secret store; the gateway config only carries
# a `${ENV:…}` (or `${FILE:…}`) reference. Spec 14 / config-reference.md
# both forbid inline-literal tokens in YAML.
assert_not_contains "raw token absent from YAML stanza" "$TOKEN" "$STANZA"

echo
echo "-- distinct-name convention for the rotation overlap phase --"
# The script's user-visible output (the heredoc body) MUST describe the
# rotation overlap using a distinct temporary name (`<name>-next`), NOT
# the same <name>. Surface this in the printout so a reader sees the
# contract without jumping to spec 14. This is the assertion that catches
# the same-name-rotation drift called out by the round-2 review.
assert_contains "rotation overlap mentions DISTINCT temp name" "DISTINCT temporary name" "$OUT"
assert_contains "rotation overlap names the <name>-next convention" '<name>-next' "$OUT"
# And: the rotation section must NOT DOCUMENT same-name rotation as a
# supported option. The validator rejects duplicate names, so a phrase
# like "mint a new value with the same <name>" would be a foot-gun — the
# round-2 finding. We check the exact wording pattern; harmless
# references that name the rejection (e.g. "the same <name> is rejected
# by src/config/yaml.rs as a duplicate") are fine and expected.
if grep -E -q 'mint .*same ?(<name>|name)' <<<"$OUT"; then
  FAIL=$((FAIL + 1))
  FAILED_ASSERTIONS+=("rotation overlap must NOT document same-name rotation as supported")
  echo "  FAIL rotation overlap must NOT document same-name rotation"
else
  PASS=$((PASS + 1))
  echo "  ok  rotation overlap does not document same-name rotation"
fi

echo
echo "-- different service name produces different env var name --"
run_mint "analytics-bot"
assert_eq "exit status for analytics-bot" "0" "$EXIT"
assert_contains "env var name analytics-bot" "SERVICE_TOKEN_ANALYTICS_BOT" "$OUT"
assert_contains "name field set to analytics-bot" 'name: analytics-bot' "$OUT"
TOKEN2="$(grep -E '^token \(store this.*\): ' <<<"$OUT" | awk '{print $NF}')"
assert_match "token shape analytics-bot" '^dbmcp_svc_[0-9a-f]{64}$' "$TOKEN2"
assert_not_contains "two mints produce different tokens" "$TOKEN" "$TOKEN2"

echo
echo "=== summary: $PASS passed, $FAIL failed ==="
if (( FAIL > 0 )); then
  echo
  echo "Failed assertions:"
  for a in "${FAILED_ASSERTIONS[@]}"; do
    echo "  - $a"
  done
  exit 1
fi
exit 0
