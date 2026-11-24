#!/usr/bin/env bash
# bin/lib/dotenv.sh: .env fills in only what the caller has not exported.
set -euo pipefail
cd "$(dirname "$0")/../.."
lib=$PWD/bin/lib/dotenv.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

printf 'A=from-dotenv\nB="two words"\nC=from-dotenv\n' > "$work/.env"
# shellcheck disable=SC2016  # expanded by the inner shell
probe='set -euo pipefail; . "$LIB"; printf "%s|%s|%s" "${A-}" "${B-}" "${C-unset}"'

got=$(cd "$work" && env -i PATH="$PATH" LIB="$lib" A=from-shell bash -c "$probe")
[[ $got == 'from-shell|two words|from-dotenv' ]] || fail "shell did not win: $got"

# An empty exported value is still the caller's choice.
got=$(cd "$work" && env -i PATH="$PATH" LIB="$lib" A= bash -c "$probe")
[[ $got == '|two words|from-dotenv' ]] || fail "empty shell value overridden: $got"

# No .env: a no-op, even with an empty environment.
rm "$work/.env"
got=$(cd "$work" && env -i LIB="$lib" /usr/bin/env bash -c "$probe")
[[ $got == '||unset' ]] || fail "no .env changed the environment: $got"

echo 'ok: bin/lib/dotenv.sh'
