#!/usr/bin/env bash
# .githooks: pre-commit refuses a staged service-token value (naming the file,
# never echoing the token) outside the exempt paths, and stays fast — no
# compile, no containers. pre-push runs clippy then the unit loop.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
token="dbmcp_svc_$(printf '%064d' 3)"

mkdir -p "$work/tools"
cat > "$work/tools/cargo" <<'STUB'
#!/usr/bin/env bash
printf 'cargo %s\n' "$*" >> "$CALLS"
STUB
cat > "$work/tools/docker" <<'STUB'
#!/usr/bin/env bash
echo 'FAIL: a hook touched Docker' >&2; exit 99
STUB
chmod +x "$work/tools/"*

repo=$work/repo
git init -q "$repo"
mkdir -p "$repo/.githooks" "$repo/bin" "$repo/tests" "$repo/config"
cp "$root/.githooks/pre-commit" "$root/.githooks/pre-push" "$repo/.githooks/"

hook() {
  : > "$work/calls"
  (cd "$repo" && PATH="$work/tools:$PATH" CALLS="$work/calls" bash ".githooks/$1") > "$work/output" 2>&1
}

printf 'servers: []\n' > "$repo/config/clean.yaml"
git -C "$repo" add config/clean.yaml
hook pre-commit || fail "clean change refused: $(<"$work/output")"
grep -qxF 'cargo fmt --all -- --check' "$work/calls" || fail 'pre-commit did not check formatting'

printf 'token: %s\n' "$token" > "$repo/config/leak.yaml"
git -C "$repo" add config/leak.yaml
if hook pre-commit; then fail 'staged token value accepted'; fi
grep -qxF 'config/leak.yaml' "$work/output" || fail 'refusal does not name the file'
! grep -qF "$token" "$work/output" || fail 'refusal echoed the token'
git -C "$repo" rm -q --cached config/leak.yaml

printf 'const T: &str = "%s";\n' "$token" > "$repo/tests/fixture.rs"
git -C "$repo" add tests/fixture.rs
hook pre-commit || fail 'token under the exempt tests/ path refused'

cat > "$repo/bin/test" <<'STUB'
#!/usr/bin/env bash
echo "bin/test $*" >> "$CALLS"
STUB
chmod +x "$repo/bin/test"
hook pre-push || fail "pre-push failed: $(<"$work/output")"
[[ $(<"$work/calls") == $'cargo clippy --all-targets --all-features -- -D warnings\nbin/test --unit' ]] \
  || fail "unexpected pre-push calls: $(<"$work/calls")"

echo 'ok: .githooks'
