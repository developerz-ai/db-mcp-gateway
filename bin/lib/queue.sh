# shellcheck shell=bash
# Sourced (from the repo root) by the bin/ scripts that compile or test: a
# repo-local queue, so concurrent agents and humans on one box take turns
# instead of thrashing it, and only one suite at a time touches the shared
# dev databases.
#
#   queue_heavy_reexec bin/<script> "$@"
#       Re-run the calling script under the machine-wide `heavy` ledger when it
#       is on PATH. For the outer full-suite runs only (bin/check, full bin/test).
#   queue_lock heavy|db "<what>"
#       Hold target/.dbmcp-<name>.lock for the rest of the process — the fd is
#       inherited, so an `exec cargo …` keeps holding it. `heavy` = a compile
#       or test run; `db` = anything that touches the dev-stack databases.
#
# A nested bin/ script skips a lock its caller already holds (DBMCP_QUEUE_HELD),
# so bin/check → bin/ci → bin/test never deadlocks on itself.
# DBMCP_NO_QUEUE=1 turns all of it off.

queue_heavy_reexec() {
  [[ ${DBMCP_NO_QUEUE:-} == 1 || -n ${DBMCP_IN_HEAVY:-} ]] && return 0
  command -v heavy >/dev/null 2>&1 || return 0
  DBMCP_IN_HEAVY=1 exec heavy --label "db-mcp-gateway ${1##*/}" "$@"
}

queue_lock() {
  local name=$1 what=$2 fd lock holder
  [[ ${DBMCP_NO_QUEUE:-} == 1 ]] && return 0
  [[ " ${DBMCP_QUEUE_HELD:-} " == *" $name "* ]] && return 0
  case "$name" in
    heavy) fd=8 ;;
    db) fd=9 ;;
    *) echo "queue: unknown lock '$name'" >&2; return 2 ;;
  esac
  if ! command -v flock >/dev/null 2>&1; then
    echo "queue: flock(1) not found; running without the $name queue" >&2
    return 0
  fi
  mkdir -p target
  lock=target/.dbmcp-$name.lock
  eval "exec $fd>>\"\$lock\""
  if ! flock -n "$fd"; then
    holder=$(cat "$lock.holder" 2>/dev/null) || holder='an unknown holder'
    printf 'queued: waiting for %s (lock %s)\n' "$holder" "$lock" >&2
    flock "$fd"
  fi
  printf 'pid %s: %s\n' "$$" "$what" > "$lock.holder"
  export DBMCP_QUEUE_HELD="${DBMCP_QUEUE_HELD:-} $name"
}
