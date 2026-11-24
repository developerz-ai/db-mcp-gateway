#!/usr/bin/env bash
# bin/lib/queue.sh: two holders of one lock serialize and the waiter names
# the holder; DBMCP_NO_QUEUE=1 opts out; a lock the caller already holds is
# not re-taken (no self-deadlock); `heavy` wraps outer runs exactly once.
# Needs flock(1) (util-linux).
set -euo pipefail
cd "$(dirname "$0")/../.."
lib=$PWD/bin/lib/queue.sh
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
command -v flock >/dev/null 2>&1 || fail 'flock(1) is required'

# A job: take the lock, log start/end around a pause the test controls.
cat > "$work/job" <<'JOB'
#!/usr/bin/env bash
set -euo pipefail
. "$LIB"
queue_lock "${LOCK:-heavy}" "job $1"
echo "start $1" >> "$LOG"
while [[ -n ${HOLD:-} && -e $HOLD ]]; do sleep 0.05; done
echo "end $1" >> "$LOG"
JOB
chmod +x "$work/job"
# The locks live in git's common dir (never Cargo's target/, which `cargo
# clean` empties under a holder).
git init -q "$work"
# Run as a fresh caller: a gate that runs this test already holds the lock.
unset DBMCP_QUEUE_HELD DBMCP_NO_QUEUE DBMCP_IN_HEAVY
job() { (cd "$work" && LIB="$lib" LOG="$work/log" "$@"); }

wait_for() {
  for _ in $(seq 100); do grep -qxF "$1" "$2" 2>/dev/null && return 0; sleep 0.05; done
  fail "timed out waiting for '$1' in $2"
}

# Serialize: B waits while A holds the lock, names A, then runs after A ends.
touch "$work/hold"
HOLD="$work/hold" job ./job A &
wait_for 'start A' "$work/log"
job ./job B 2> "$work/b.err" &
b=$!
for _ in $(seq 100); do [[ -s $work/b.err ]] && break; sleep 0.05; done
grep -qE '^queued: waiting for pid [0-9]+: job A \(lock \.git/dbmcp-heavy\.lock\)$' "$work/b.err" \
  || fail "waiter line wrong: $(<"$work/b.err")"
! grep -qxF 'start B' "$work/log" || fail 'B started while A held the lock'
rm "$work/hold"
wait "$b"
[[ $(<"$work/log") == $'start A\nend A\nstart B\nend B' ]] || fail "not serialized: $(<"$work/log")"
wait

# The db lock is independent of the heavy one.
: > "$work/log"; touch "$work/hold"
HOLD="$work/hold" job ./job A &
wait_for 'start A' "$work/log"
LOCK=db job ./job D 2> "$work/d.err"
[[ ! -s $work/d.err ]] || fail 'db lock waited on the heavy lock'
rm "$work/hold"; wait

# Opt-out: runs at once even while the lock is held.
: > "$work/log"; touch "$work/hold"
HOLD="$work/hold" job ./job A &
wait_for 'start A' "$work/log"
DBMCP_NO_QUEUE=1 job ./job C 2> "$work/c.err"
grep -qxF 'end C' "$work/log" || fail 'opt-out still waited'
[[ ! -s $work/c.err ]] || fail 'opt-out printed a queue line'
rm "$work/hold"; wait

# Nested: a child of a holder skips the lock instead of deadlocking.
: > "$work/log"
cat > "$work/outer" <<'OUTER'
#!/usr/bin/env bash
set -euo pipefail
. "$LIB"
queue_lock heavy outer
timeout 5 ./job inner
OUTER
chmod +x "$work/outer"
job ./outer || fail 'nested holder deadlocked'
grep -qxF 'end inner' "$work/log" || fail 'nested job did not run'

# heavy: the script re-runs once under `heavy`, never recursively.
mkdir -p "$work/tools"
cat > "$work/tools/heavy" <<'HEAVY'
#!/usr/bin/env bash
echo "heavy $*" >> "$LOG"
[[ $1 == --label ]] && shift 2
exec "$@"
HEAVY
chmod +x "$work/tools/heavy"
cat > "$work/outer-full" <<'FULL'
#!/usr/bin/env bash
set -euo pipefail
. "$LIB"
queue_heavy_reexec ./outer-full "$@"
echo "ran $*" >> "$LOG"
FULL
chmod +x "$work/outer-full"
: > "$work/log"
PATH="$work/tools:$PATH" job ./outer-full x
[[ $(<"$work/log") == $'heavy --label db-mcp-gateway outer-full ./outer-full x\nran x' ]] \
  || fail "heavy wrap wrong: $(<"$work/log")"
: > "$work/log"
PATH="$work/tools:$PATH" DBMCP_NO_QUEUE=1 job ./outer-full y
[[ $(<"$work/log") == 'ran y' ]] || fail 'opt-out still used heavy'

# `cargo clean` cannot unlink a held lock: nothing of it lives under target/.
[[ -e $work/.git/dbmcp-heavy.lock && ! -e $work/target ]] || fail 'the lock is not in the git dir'

echo 'ok: bin/lib/queue.sh'
