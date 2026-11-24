# shellcheck shell=bash
# Sourced (at top level, from the repo root) by the bin/ scripts: load .env
# without letting it override the caller. `set -a; . ./.env` alone makes .env
# win over `FOO=1 bin/test`; re-applying the exported shell environment after
# it restores the caller's values, and .env fills in only what was unset.
# Top level, not a function: `declare` inside a function would make the
# restored variables local to it.
if [[ -f .env ]]; then
  __dotenv_shell=$(export -p | grep -v '^declare -[a-zA-Z]*r' || true)
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
  eval "$__dotenv_shell"
  unset __dotenv_shell
fi
