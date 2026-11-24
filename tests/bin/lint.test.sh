#!/usr/bin/env bash
# bin/lint --lib: the fmt check plus ONE clippy pass over lib + bins, nothing
# else; plain bin/lint keeps CI's full sequence (its exact calls are pinned by
# check.test.sh); an unknown flag is a usage error before cargo runs.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

mkdir -p "$work/repo/bin" "$work/tools"
cp bin/lint "$work/repo/bin/"
cp -r bin/lib "$work/repo/bin/"
printf '#!/usr/bin/env bash\necho check-scrub-features >> "$CALLS"\n' > "$work/repo/bin/check-scrub-features"
printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" "${0##*/}" "$*" >> "$CALLS"\n' > "$work/tools/cargo"
chmod +x "$work/repo/bin/check-scrub-features" "$work/tools/cargo"

lint() {
  : > "$work/calls"
  (cd "$work/repo" && PATH="$work/tools:$PATH" CALLS="$work/calls" DBMCP_NO_QUEUE=1 bash bin/lint "$@") > "$work/out" 2>&1
}

lint --lib || fail "bin/lint --lib failed: $(<"$work/out")"
want='cargo fmt --all -- --check
cargo clippy --profile ci --lib --bins --all-features -- -D warnings'
[[ $(<"$work/calls") == "$want" ]] || fail "unexpected --lib calls: $(<"$work/calls")"

lint || fail 'plain bin/lint failed'
[[ $(wc -l < "$work/calls") == 4 && $(tail -1 "$work/calls") == check-scrub-features ]] \
  || fail "plain bin/lint is not the full sequence: $(<"$work/calls")"

rc=0; lint --bogus || rc=$?
[[ $rc == 2 && ! -s $work/calls ]] || fail "unknown flag exited $rc or ran cargo"

echo 'ok: bin/lint --lib'
