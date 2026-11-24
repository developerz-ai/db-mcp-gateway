#!/usr/bin/env bash
# Isolated tests for bin/seed: a stub docker records calls. Pins: it never
# runs `compose up` (that can recreate a container in use), refuses with 75
# when target-db is down, creates `shop` only when missing, and loads the
# committed seed into `shop`, never into the tests' database.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

mkdir -p "$work/repo/bin/lib" "$work/repo/examples/demo" "$work/tools"
cp bin/seed "$work/repo/bin/"
cp bin/lib/dotenv.sh "$work/repo/bin/lib/"
cp examples/demo/seed.sql "$work/repo/examples/demo/"
for tool in bash dirname grep cat; do
  ln -s "$(command -v "$tool")" "$work/tools/$tool"
done
cat > "$work/tools/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CALLS"
case "$*" in
  *' ps --status running --services') printf '%s\n' ${RUNNING:-} ;;
  *"SELECT 1 FROM pg_database WHERE datname = 'shop'") printf '%s\n' "${SHOP_EXISTS:-}" ;;
  *' -d shop') [[ $(cat) == *'CREATE TABLE IF NOT EXISTS orders'* ]] || exit 9 ;;
esac
STUB
chmod +x "$work/tools/docker"

seed() {
  : > "$work/calls"
  (cd "$work/repo" && env -i PATH="$work/tools" CALLS="$work/calls" "$@" bash bin/seed) > "$work/output" 2>&1
}

rc=0; seed || rc=$?
[[ $rc == 75 ]] || fail "target-db down exited $rc, want 75"

seed RUNNING='state-db target-db' || fail 'seed failed with target-db up'
grep -qF -- '-d app -c CREATE DATABASE shop' "$work/calls" || fail 'missing shop database not created'
grep -qxF -- 'compose -f docker-compose.dev.yml exec -T target-db psql -v ON_ERROR_STOP=1 -q -U app -d shop' "$work/calls" \
  || fail 'seed not loaded into shop'

seed RUNNING=target-db SHOP_EXISTS=1 TARGET_DB_USER=owner || fail 'seed failed with shop present'
! grep -qF 'CREATE DATABASE' "$work/calls" || fail 'existing shop database re-created'
grep -qF -- '-U owner -d shop' "$work/calls" || fail 'TARGET_DB_USER ignored'

! grep -qE '(^| )up( |$)' "$work/calls" || fail 'bin/seed ran compose up'
echo 'ok: bin/seed'
