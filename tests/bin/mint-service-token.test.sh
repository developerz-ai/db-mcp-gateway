#!/usr/bin/env bash
# tests/bin/mint-service-token.test.sh — bin/mint-service-token is a thin
# wrapper over `db-mcp-gateway mint-service-token`. This checks the wrapper
# only (argument forwarding, exit status, binary selection) against a stub, so
# it needs no toolchain. The token contract itself — shape, CSPRNG, the YAML
# stanza carrying a reference and never the value, usage errors — is tested
# against the real binary in tests/it_offline/cli_mint.rs and src/cli/mint.rs.
#
#   bash tests/bin/mint-service-token.test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/bin/mint-service-token"
[[ -x "$SCRIPT" ]] || { echo "FAIL: $SCRIPT not found or not executable" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mint-wrapper.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
STUB="$WORK/db-mcp-gateway"
# The stub records its argv, one per line, and exits with $STUB_EXIT.
cat >"$STUB" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$STUB_ARGS"
exit "${STUB_EXIT:-0}"
STUB
chmod +x "$STUB"

PASS=0
FAIL=0
check() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    PASS=$((PASS + 1)); echo "  ok  $label"
  else
    FAIL=$((FAIL + 1)); echo "  FAIL $label: expected <$expected>, got <$actual>"
  fi
}

export STUB_ARGS="$WORK/args"

echo "-- DB_MCP_GATEWAY_BIN: forwards the subcommand and the name verbatim --"
DB_MCP_GATEWAY_BIN="$STUB" "$SCRIPT" "ci-bot"
check "argv" $'mint-service-token\nci-bot' "$(cat "$STUB_ARGS")"

echo "-- an argument with spaces stays one argument --"
DB_MCP_GATEWAY_BIN="$STUB" "$SCRIPT" "with space"
check "argv" $'mint-service-token\nwith space' "$(cat "$STUB_ARGS")"

echo "-- the binary's exit status is the wrapper's (2 = usage) --"
set +e
STUB_EXIT=2 DB_MCP_GATEWAY_BIN="$STUB" "$SCRIPT" "Bad_Name"
status=$?
set -e
check "exit status" "2" "$status"

# Fallbacks run on a PATH of exactly these tools, against a copy of the
# script in a scratch checkout (its target/ is ours to fill).
mkdir -p "$WORK/repo/bin" "$WORK/tools" "$WORK/path"
cp "$SCRIPT" "$WORK/repo/bin/"
for tool in bash dirname; do ln -s "$(command -v "$tool")" "$WORK/tools/$tool"; done
cp "$STUB" "$WORK/path/db-mcp-gateway"
fallback() {
  rm -f "$STUB_ARGS"
  env -i PATH="$WORK/tools:$WORK/path" STUB_ARGS="$STUB_ARGS" \
    bash "$WORK/repo/bin/mint-service-token" bot > "$WORK/out" 2>&1
}

echo "-- cargo present: the checkout's source wins over db-mcp-gateway on PATH --"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" cargo "$@" > "$STUB_ARGS"\n' > "$WORK/tools/cargo"
chmod +x "$WORK/tools/cargo"
fallback
check "argv via cargo run" "cargo run --quiet --manifest-path $WORK/repo/Cargo.toml --bin db-mcp-gateway -- mint-service-token bot" \
  "$(tr '\n' ' ' < "$STUB_ARGS" | sed 's/ $//')"
rm "$WORK/tools/cargo"

echo "-- no cargo: the checkout's newest build wins over PATH --"
mkdir -p "$WORK/repo/target/debug" "$WORK/repo/target/release"
printf '#!/usr/bin/env bash\necho release "$@" > "$STUB_ARGS"\n' > "$WORK/repo/target/release/db-mcp-gateway"
printf '#!/usr/bin/env bash\necho debug "$@" > "$STUB_ARGS"\n' > "$WORK/repo/target/debug/db-mcp-gateway"
chmod +x "$WORK/repo/target/"*/db-mcp-gateway
touch -d '1 hour ago' "$WORK/repo/target/release/db-mcp-gateway"
fallback
check "newest build" "debug mint-service-token bot" "$(cat "$STUB_ARGS")"
rm -r "$WORK/repo/target"

echo "-- nothing in the checkout: PATH, with a notice --"
fallback
check "argv via PATH" $'mint-service-token\nbot' "$(cat "$STUB_ARGS")"
check "PATH notice" "1" "$(grep -c 'from PATH' "$WORK/out")"

echo "-- nothing at all: exit 2 --"
rm "$WORK/path/db-mcp-gateway"
set +e; fallback; status=$?; set -e
check "exit status" "2" "$status"

echo "=== summary: $PASS passed, $FAIL failed ==="
(( FAIL == 0 ))
