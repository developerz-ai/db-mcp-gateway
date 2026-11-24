#!/usr/bin/env bash
# Isolated tests for bin/run: no Docker, cargo or database is invoked — stubs
# on PATH record each call. Pins: dev defaults, .env vs shell precedence, the
# one-time token mint, the port-rendered config, and starting only the
# services that are not running.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

fixture() {
  rm -rf "$work/repo" "$work/tools"
  mkdir -p "$work/repo/bin/lib" "$work/repo/config" "$work/tools"
  cp bin/run "$work/repo/bin/"
  cp bin/lib/dotenv.sh "$work/repo/bin/lib/"
  cp config/dev.yaml "$work/repo/config/"
  for tool in bash dirname grep sed mkdir cat mktemp mv rm; do
    ln -s "$(command -v "$tool")" "$work/tools/$tool"
  done
  cat > "$work/tools/stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$CALLS"
case "$name $*" in
  'docker compose '*' ps --status running --services') printf '%s\n' ${RUNNING:-} ;;
  'openssl rand -hex 32')
    # A failing openssl may still have written part of its output.
    if [[ -n ${OPENSSL_FAIL:-} ]]; then printf 'abc'; exit 1; fi
    printf '%064d\n' 7 ;;
  'cargo '*)
    # The environment the gateway would boot with.
    for var in STATE_DB_URL TARGET_DB_PASSWORD TARGET_DB_RO_PASSWORD TLS_DISABLED OIDC_ISSUER OIDC_CLIENT_ID \
      OIDC_CLIENT_SECRET ALLOW_INSECURE_SIGNING_KEY DBMCP_DEV_SERVICE_TOKEN; do
      printf 'env %s=%s\n' "$var" "${!var-<unset>}" >> "$CALLS"
    done ;;
esac
STUB
  chmod +x "$work/tools/stub"
  for tool in docker cargo openssl; do ln -s stub "$work/tools/$tool"; done
  cat > "$work/repo/bin/seed" <<'STUB'
#!/usr/bin/env bash
echo bin/seed >> "$CALLS"
STUB
  chmod +x "$work/repo/bin/seed"
  : > "$work/calls"
}

run() {
  (cd "$work/repo" && env -i PATH="$work/tools" HOME="$work" CALLS="$work/calls" "$@" bash bin/run) \
    > "$work/output" 2>&1
}

expect_call() { grep -qxF -- "$1" "$work/calls" || { cat "$work/calls" >&2; fail "missing call: $1"; }; }
reject_call() { ! grep -qF -- "$1" "$work/calls" || { cat "$work/calls" >&2; fail "unexpected call: $1"; }; }

# Defaults, nothing running: both services started, committed config used, token minted.
fixture
run || fail 'bin/run failed with defaults'
expect_call 'docker compose -f docker-compose.dev.yml up -d --wait state-db target-db'
expect_call 'cargo run --bin db-mcp-gateway -- --config config/dev.yaml'
expect_call 'env STATE_DB_URL=postgres://gateway:gateway-dev-only@localhost:5433/gateway'
expect_call 'env TLS_DISABLED=true'
expect_call 'env OIDC_ISSUER=http://localhost:5556'
expect_call 'env OIDC_CLIENT_SECRET=dev-only-oidc-secret'
# The gateway gets only the read-only login; the owner password stays with bin/seed.
expect_call 'env TARGET_DB_RO_PASSWORD=gateway-ro-dev-only'
expect_call 'env TARGET_DB_PASSWORD=<unset>'
# bin/seed (the read-only role) runs after the stack is up and before the gateway boots.
[[ $(grep -nE '^(docker compose .* up |bin/seed|cargo run)' "$work/calls" | cut -d: -f2 | cut -c1-8) == $'docker c\nbin/seed\ncargo ru' ]] \
  || { cat "$work/calls" >&2; fail 'bin/seed not between compose up and cargo run'; }
token=$(<"$work/repo/target/dev/service-token")
[[ $token =~ ^dbmcp_svc_[0-9a-f]{64}$ ]] || fail 'minted token has the wrong shape'
[[ $(stat -c %a "$work/repo/target/dev/service-token") == 600 ]] || fail 'token file is not 0600'
expect_call "env DBMCP_DEV_SERVICE_TOKEN=$token"

# The token is minted once, then reused.
: > "$work/calls"
run || fail 'second bin/run failed'
reject_call 'openssl rand'
expect_call "env DBMCP_DEV_SERVICE_TOKEN=$token"

# Running services are never re-upped (an `up` under other env recreates them).
: > "$work/calls"
run RUNNING='state-db target-db' || fail 'bin/run failed with the stack running'
reject_call 'up -d --wait'
: > "$work/calls"
run RUNNING='state-db' || fail 'bin/run failed with target-db stopped'
expect_call 'docker compose -f docker-compose.dev.yml up -d --wait target-db'

# .env fills unset values; the shell wins over .env; a moved port renders a copy.
fixture
printf 'TARGET_DB_PORT=5999\nTLS_DISABLED=from-dotenv\nOIDC_CLIENT_ID=from-dotenv\n' > "$work/repo/.env"
run OIDC_CLIENT_ID=from-shell || fail 'bin/run failed with .env'
expect_call 'env TLS_DISABLED=from-dotenv'
expect_call 'env OIDC_CLIENT_ID=from-shell'
expect_call 'cargo run --bin db-mcp-gateway -- --config target/dev/config.yaml'
grep -qx '    port: 5999' "$work/repo/target/dev/config.yaml" || fail 'rendered config keeps the old port'
diff <(sed 's/^    port: 5999$/    port: 5434/' "$work/repo/target/dev/config.yaml") config/dev.yaml >/dev/null || fail 'rendered config changed other lines'

# --idp adds Dex under its profile; other flags reach cargo.
fixture
run || true
: > "$work/calls"
(cd "$work/repo" && env -i PATH="$work/tools" HOME="$work" CALLS="$work/calls" bash bin/run --idp --release) \
  > "$work/output" 2>&1 || fail 'bin/run --idp failed'
expect_call 'docker compose -f docker-compose.dev.yml --profile idp up -d --wait state-db target-db dex'
expect_call 'cargo run --bin db-mcp-gateway --release -- --config config/dev.yaml'

# A failed mint leaves no token file (and no temp file) behind, and boots nothing.
fixture
if run OPENSSL_FAIL=1; then fail 'bin/run succeeded with openssl failing'; fi
[[ -z $(ls -A "$work/repo/target/dev") ]] || fail "failed mint left files: $(ls -A "$work/repo/target/dev")"
reject_call 'cargo'
run || fail 'bin/run failed after a failed mint'
[[ $(<"$work/repo/target/dev/service-token") =~ ^dbmcp_svc_[0-9a-f]{64}$ ]] || fail 'retry did not mint a full token'

# An owner password exported by the shell or .env never reaches the gateway.
fixture
run TARGET_DB_PASSWORD=owner-from-shell || fail 'bin/run failed with an owner password in the shell'
expect_call 'env TARGET_DB_PASSWORD=<unset>'
fixture
printf 'TARGET_DB_PASSWORD=owner-from-dotenv\n' > "$work/repo/.env"
run || fail 'bin/run failed with an owner password in .env'
expect_call 'env TARGET_DB_PASSWORD=<unset>'

# A non-numeric port is refused before anything starts.
fixture
if run TARGET_DB_PORT=abc; then fail 'non-numeric TARGET_DB_PORT accepted'; fi
reject_call 'cargo'

echo 'ok: bin/run'
