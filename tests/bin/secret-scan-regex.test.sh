#!/usr/bin/env bash
# tests/bin/secret-scan-regex.test.sh — pins the regex intent behind the
# secret-scan CI guard (.github/workflows/ci.yml :: secret-scan) and spec 14.
#
# The guard enforces "no literal dbmcp_svc_ service tokens in committed YAML"
# with the regex `dbmcp_svc_[0-9a-f]{64}`. This test fixes what that regex
# accepts and rejects so a future loosening (or tightening past real tokens)
# is caught as a regression of issue #190.
#
# Run:
#   bash tests/bin/secret-scan-regex.test.sh
#
# Exits 0 on success, 1 on the first failed assertion. Self-contained: no
# network, no DB, no cargo. Requires bash >= 4 (uses [[ ... =~ ... ]]).
set -euo pipefail

# The exact UNANCHORED ERE the CI guard greps with (ci.yml :: secret-scan).
# Mirroring the guard verbatim means a 64-hex substring of a longer run also
# matches here, exactly as the guard would flag it — boot rejects malformed
# bodies via ServiceTokenError::WeakToken anyway, so over-matching is safe.
PATTERN='dbmcp_svc_[0-9a-f]{64}'

PASS=0
FAIL=0
FAILED_ASSERTIONS=()

# Assert $2 matches the anchored pattern (the guard SHOULD catch it).
assert_match() {
  local name="$1" value="$2"
  if [[ "$value" =~ $PATTERN ]]; then
    PASS=$((PASS + 1))
    echo "  ok  $name"
  else
    FAIL=$((FAIL + 1))
    FAILED_ASSERTIONS+=("$name (value: <$value> should match)")
    echo "  FAIL $name"
    echo "       value:    <$value>"
    echo "       pattern:  $PATTERN"
  fi
}

# Assert $2 does NOT match (the guard should not fire on a non-token).
assert_no_match() {
  local name="$1" value="$2"
  if [[ "$value" =~ $PATTERN ]]; then
    FAIL=$((FAIL + 1))
    FAILED_ASSERTIONS+=("$name (value: <$value> should NOT match)")
    echo "  FAIL $name"
    echo "       value:    <$value>"
    echo "       pattern:  $PATTERN"
  else
    PASS=$((PASS + 1))
    echo "  ok  $name"
  fi
}

# Helpers to build hex runs of an exact length without depending on printf
# supporting brace-expansion at the call site.
hex_run() {
  # $1 = count of hex chars, $2 = the hex char to repeat (0-9a-f)
  local n="$1" c="$2"
  printf '%s' "$c"; printf '%*s' "$((n - 1))" '' | tr ' ' "$c"
}

# Well-formed tokens: 10-char prefix + exactly 64 lowercase hex.
GOOD_TOKEN="dbmcp_svc_$(hex_run 64 0)"
GOOD_TOKEN2="dbmcp_svc_$(hex_run 64 f)"
GOOD_TOKEN3="dbmcp_svc_0123456789abcdef$(hex_run 48 0)"

echo "=== secret-scan regex (issue #190) ==="

echo
echo "-- well-formed tokens match (guard would catch them) --"
assert_match "64 lowercase zeros" "$GOOD_TOKEN"
assert_match "64 lowercase f" "$GOOD_TOKEN2"
assert_match "mixed hex, 64 total" "$GOOD_TOKEN3"

echo
echo "-- malformed tokens do NOT match (guard stays silent) --"
assert_no_match "63 hex (too short)" "dbmcp_svc_$(hex_run 63 0)"
# 65 hex contains a 64-hex substring, so the unanchored guard MATCHES it
# (over-match is safe — boot rejects the malformed body anyway). Mirrors the
# guard exactly; the earlier anchored variant misrepresented this.
assert_match "65 hex (substring match)" "dbmcp_svc_$(hex_run 65 0)"
assert_no_match "uppercase hex rejected" "dbmcp_svc_$(hex_run 64 A)"
assert_no_match "non-hex body rejected" "dbmcp_svc_$(hex_run 64 z)"
assert_no_match "wrong prefix rejected" "dbmsvc___$(hex_run 64 0)"
assert_no_match "missing underscore rejected" "dbmcpsvc$(hex_run 64 0)"
assert_no_match "ENV reference is not a literal" '${ENV:SERVICE_TOKEN_CI_BOT}'
assert_no_match "FILE reference is not a literal" '${FILE:/etc/dbmcp/svc}'

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
