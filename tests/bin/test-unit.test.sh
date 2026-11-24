#!/usr/bin/env bash
# Isolated tests for `bin/test --unit`: it must reach cargo without Docker on
# PATH, select the lib, bin and it_offline targets only, and pass extra args.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

mkdir -p "$work/repo/bin/lib" "$work/tools"
cp bin/test "$work/repo/bin/"
cp bin/lib/dotenv.sh bin/lib/queue.sh "$work/repo/bin/lib/"
for tool in bash dirname; do
  ln -s "$(command -v "$tool")" "$work/tools/$tool"
done
cat > "$work/tools/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$CALLS"
STUB
chmod +x "$work/tools/cargo"

unit() {
  : > "$work/calls"
  (cd "$work/repo" && env -i PATH="$work/tools" CALLS="$work/calls" bash bin/test --unit "$@") > "$work/output" 2>&1
}

# No docker stub exists: reaching cargo proves Docker is never probed.
unit -- --nocapture || fail 'bin/test --unit failed without Docker'
[[ $(<"$work/calls") == 'cargo test --lib --bins --test it_offline --all-features -- --nocapture' ]] \
  || fail "unexpected cargo test call: $(<"$work/calls")"

ln -s cargo "$work/tools/cargo-nextest"
unit || fail 'bin/test --unit failed with nextest'
[[ $(<"$work/calls") == 'cargo nextest run --lib --bins --test it_offline --all-features' ]] \
  || fail "unexpected nextest call: $(<"$work/calls")"

echo 'ok: bin/test --unit'
