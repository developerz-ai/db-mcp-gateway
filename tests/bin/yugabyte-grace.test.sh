#!/usr/bin/env bash
# target-yugabyte stops with a 120 s grace: the compose service declares it,
# and no script or workflow stops the container with a shorter explicit one
# (a SIGKILL mid-flush leaves a WAL without its footer and a wedged tablet).
set -euo pipefail
cd "$(dirname "$0")/../.."

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

service=$(awk '/^  target-yugabyte:$/ {on=1; next} on && /^  [^ #]/ {exit} on' docker-compose.dev.yml)
[[ -n $service ]] || fail 'docker-compose.dev.yml has no target-yugabyte service'
grep -qx '    stop_grace_period: 120s' <<<"$service" \
  || fail 'target-yugabyte must declare stop_grace_period: 120s'

# An explicit `stop`/`down`/`restart` that can reach target-yugabyte (a docker
# stop naming it, or compose with the yugabyte profile) must pass -t 120.
offenders=$(git grep -nE '(docker (container )?(stop|restart)[^|;&]*yugabyte|--profile yugabyte[^|;&]* (stop|down|restart)\b)' \
  -- bin .github/workflows tests/bin ':!tests/bin/yugabyte-grace.test.sh' \
  | grep -vE -- '(-t|--timeout)[ =]?120\b' || true)
[[ -z $offenders ]] || fail "target-yugabyte stopped without a 120 s grace:
$offenders"

echo 'ok: target-yugabyte stop grace'
