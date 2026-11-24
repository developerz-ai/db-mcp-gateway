#!/usr/bin/env bash
# End-to-end smoke for examples/demo (needs Docker; pulls images): bring the
# demo up under a throwaway project name, take the printed `claude mcp add`
# line, make one real tools/call run_query with its token, assert rows and the
# audit row; check the session signing key is minted per project, then bring
# up the `sso` profile and reach Dex through its published port; then remove
# the project and its volumes. Needs host ports DEMO_PORT and 5556 free.
#   DEMO_PORT      host port (default 18443, away from bin/run's 8443)
#   GATEWAY_IMAGE  image under test (default: the one the demo pins)
set -euo pipefail
cd "$(dirname "$0")/../../examples/demo"

port=${DEMO_PORT:-18443}

# A release PR bumps the pinned tag to the crate's next version before that
# image exists (the tag is cut after merge). Only that case — the pin is the
# crate's own version and no `v<version>` tag exists yet — tests the same
# code through `:main`, which a release PR does not change. Any other
# unpullable pin (a typo, a registry error) fails the test.
if [[ -z "${GATEWAY_IMAGE:-}" ]]; then
  pinned=$(sed -n 's/.*image: \${GATEWAY_IMAGE:-\([^}]*\)}.*/\1/p' docker-compose.yml | head -1)
  version=$(sed -n 's/^version = "\(.*\)"/\1/p' ../../Cargo.toml | head -1)
  # Cheap local checks first; origin is asked only when a fallback is
  # possible. `ls-remote --exit-code` answers 2 only for "no such ref"; a
  # lookup error (no network, no origin) is not proof the release is uncut.
  if [[ -n "$pinned" && -n "$version" && "${pinned##*:}" == "$version" ]] &&
    ! git -C ../.. rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
    remote=0
    timeout 20 git -C ../.. ls-remote --exit-code --tags origin "v$version" >/dev/null 2>&1 || remote=$?
    if [[ $remote -eq 2 ]]; then
      export GATEWAY_IMAGE=${pinned%:*}:main
      printf 'note: release v%s is not cut yet; testing %s\n' "$version" "$GATEWAY_IMAGE" >&2
    fi
  fi
fi
compose=(docker compose -p "db-mcp-gateway-demo-test-$$")
export DEMO_PORT=$port
trap '"${compose[@]}" --profile sso down -v >/dev/null 2>&1 || true' EXIT

# Never dumps container logs: `ready` prints the bearer token, and the leak
# checks below fail precisely when a log holds a secret.
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

"${compose[@]}" up -d --wait >/dev/null 2>&1 || fail 'demo did not come up'

# The walkthrough's order: `up --wait` returned on a healthy gateway; the
# one-shot `ready` prints the line.
printed=$("${compose[@]}" run --rm -T ready 2>/dev/null) || fail 'the ready service did not exit 0'
line=$(grep -F 'claude mcp add' <<<"$printed") || fail 'no claude mcp add line printed'
# Without the sso profile nothing publishes Dex's port.
[[ -z $("${compose[@]}" ps -q dex-port) ]] || fail 'dex-port runs without the sso profile'
! "${compose[@]}" port gateway 5556 >/dev/null 2>&1 || fail 'the gateway publishes 5556 without the sso profile'
[[ $line == *"--transport http demo-db http://localhost:${port}/mcp --header \"Authorization: Bearer dbmcp_svc_"* ]] \
  || fail 'unexpected claude mcp add line'
token=$(grep -oE 'dbmcp_svc_[0-9a-f]{64}' <<<"$line")

body='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_query","arguments":{"server":"demo","database":"shop","sql":"SELECT name FROM customers ORDER BY id LIMIT 2"}}}'
response=$(printf 'header = "Authorization: Bearer %s"\n' "$token" \
  | curl -sS --config - -H 'Content-Type: application/json' --data-binary "$body" "http://localhost:${port}/mcp")
[[ $response == *'"isError":false'* && $response == *'Ada Lovelace'* && $response == *'Grace Hopper'* ]] \
  || fail "run_query returned no rows: $response"

audit=$("${compose[@]}" exec -T state-db psql -U gateway -d gateway -tAc \
  "SELECT count(*) FROM audit_calls WHERE user_sub = 'service:demo' AND tool = 'run_query' AND outcome = 'success'")
[[ $audit == 1 ]] || fail "expected one audit row, found <$audit>"

# The signing key: random per project, in the shared volume, never in the
# container's configured environment (docker inspect) or the gateway log.
key=$("${compose[@]}" run --rm --no-deps -T --entrypoint sh mint-token -c 'cat /run/demo-secrets/session-signing-key') \
  || fail 'no session signing key in the demo volume'
[[ $key =~ ^[0-9a-f]{64}$ ]] || fail 'the session signing key is not 32 random bytes in hex'
config_env=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$("${compose[@]}" ps -q gateway)")
[[ $config_env != *SESSION_SIGNING_KEY* ]] || fail 'the signing key is in the container configuration'
gateway_log=$("${compose[@]}" logs gateway 2>&1)
[[ $gateway_log != *"$key"* ]] || fail 'leak found at the gateway log: it holds the signing key'

# SSO profile, the walkthrough's way (a fresh `--profile sso up`): a new
# volume mints a new key; Dex answers through the published loopback port,
# connection after connection (the relay keeps listening).
"${compose[@]}" down -v >/dev/null 2>&1 || fail 'demo did not stop'
"${compose[@]}" --profile sso up -d --wait >/dev/null 2>&1 || fail 'the sso profile did not come up'
fresh=$("${compose[@]}" run --rm --no-deps -T --entrypoint sh mint-token -c 'cat /run/demo-secrets/session-signing-key') \
  || fail 'no session signing key in the sso run'
[[ $fresh =~ ^[0-9a-f]{64}$ && $fresh != "$key" ]] || fail 'a new demo volume did not mint a new signing key'
discovery=http://localhost:5556/.well-known/openid-configuration
for _ in $(seq 1 30); do
  curl -fsS -m 2 "$discovery" >/dev/null 2>&1 && break
  sleep 1
done
for _ in 1 2 3; do
  oidc=$(curl -fsS -m 5 "$discovery") || fail 'Dex unreachable on localhost:5556'
  [[ $oidc =~ \"issuer\":\ ?\"http://localhost:5556\" ]] || fail "unexpected Dex discovery: $oidc"
done

echo 'ok: examples/demo (run_query returned rows, audited; random signing key; Dex via sso profile)'
