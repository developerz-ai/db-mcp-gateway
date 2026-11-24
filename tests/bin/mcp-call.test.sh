#!/usr/bin/env bash
# Isolated tests for bin/mcp-call: a stub curl records its argv and stdin and
# answers with a canned body. Pins: the JSON-RPC body, the default URL, the
# token never on curl's command line, and the exit status contract.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
token="dbmcp_svc_$(printf '%064d' 1)"

mkdir -p "$work/repo/bin/lib" "$work/repo/target/dev" "$work/tools"
cp bin/mcp-call "$work/repo/bin/"
cp bin/lib/dotenv.sh "$work/repo/bin/lib/"
printf '%s' "$token" > "$work/repo/target/dev/service-token"
for tool in bash dirname grep cat; do
  ln -s "$(command -v "$tool")" "$work/tools/$tool"
done
cat > "$work/tools/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$WORK/argv"
cat > "$WORK/stdin"
printf '%s' "${RESPONSE:-{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[],\"isError\":false}}}"
STUB
chmod +x "$work/tools/curl"

call() {
  (cd "$work/repo" && env -i PATH="$work/tools" WORK="$work" "${env[@]}" bash bin/mcp-call "$@") \
    > "$work/output" 2>&1
}
env=()

call run_query '{"server":"local","database":"shop","sql":"select 1"}' || fail 'a successful call exited non-zero'
argv=$(<"$work/argv")
[[ $argv == *'--data-binary {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_query","arguments":{"server":"local","database":"shop","sql":"select 1"}}}'* ]] \
  || fail "unexpected body: $argv"
[[ $argv == *' http://127.0.0.1:8443/mcp' ]] || fail "unexpected default URL: $argv"
[[ $argv != *"$token"* ]] || fail 'token on the curl command line'
grep -qxF "header = \"Authorization: Bearer $token\"" "$work/stdin" || fail 'token not sent on stdin'

# Arguments default to {}; --list is tools/list.
call list_servers || fail 'list_servers failed'
[[ $(<"$work/argv") == *'"params":{"name":"list_servers","arguments":{}}'* ]] || fail 'empty arguments not {}'
call --list || fail '--list failed'
[[ $(<"$work/argv") == *'"method":"tools/list"}'* ]] || fail '--list is not tools/list'

# GATEWAY_BIND / MCP_PATH move the default; MCP_URL and DBMCP_TOKEN override.
env=(GATEWAY_BIND=0.0.0.0:9443 MCP_PATH=/gw)
call list_servers || fail 'custom bind failed'
[[ $(<"$work/argv") == *' http://127.0.0.1:9443/gw' ]] || fail 'GATEWAY_BIND/MCP_PATH ignored'
env=(MCP_URL=http://localhost:18443/mcp DBMCP_TOKEN=other-token)
call list_servers || fail 'MCP_URL override failed'
[[ $(<"$work/argv") == *' http://localhost:18443/mcp' ]] || fail 'MCP_URL ignored'
grep -qxF 'header = "Authorization: Bearer other-token"' "$work/stdin" || fail 'DBMCP_TOKEN ignored'
env=()

# A tool error or JSON-RPC error exits 1; bad usage exits 2.
env=('RESPONSE={"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":true}}')
if call run_query '{}'; then fail 'isError result exited 0'; fi
env=('RESPONSE={"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"x"}}')
if call run_query '{}'; then fail 'JSON-RPC error exited 0'; fi
env=()
for bad in '' 'Run-Query' '-x' 'a"b'; do
  rc=0; call "$bad" || rc=$?
  [[ $rc == 2 ]] || fail "usage error for <$bad> exited $rc"
done

# No token anywhere: refuse before calling.
rm "$work/repo/target/dev/service-token" "$work/argv"
rc=0; call list_servers || rc=$?
[[ $rc == 2 && ! -e $work/argv ]] || fail 'missing token did not stop before curl'

echo 'ok: bin/mcp-call'
