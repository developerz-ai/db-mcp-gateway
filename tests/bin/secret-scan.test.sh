#!/usr/bin/env bash
# bin/secret-scan over the whole index (CI's secret-scan job, bin/ci): a token
# in a tracked file's contents, its NAME or a symlink's TARGET fails the scan
# (exit 1) and is reported by location only — `path:line` for contents, the
# masked path otherwise. Exempt paths pass; a scanner that cannot run exits 2,
# never 0. The --staged mode is pinned by githooks*.test.sh.
set -euo pipefail

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
cd "$(dirname "$0")/../.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
token_a="dbmcp_svc_$(printf '%064d' 1)"
token_b="dbmcp_svc_$(printf '%064d' 2)"

repo=$work/repo
git init -q "$repo"
mkdir -p "$repo/bin" "$repo/config" "$repo/tests"
cp "$root/bin/secret-scan" "$repo/bin/"

scan() {
  local rc=0
  (cd "$repo" && PATH="${1:-}$PATH" bash bin/secret-scan) > "$work/output" 2>&1 || rc=$?
  ! grep -qE 'dbmcp_svc_[0-9a-f]{64}' "$work/output" || fail "report echoed a token: $(<"$work/output")"
  return "$rc"
}
expect_rc() {
  local want=$1 rc=0
  shift
  scan "$@" || rc=$?
  [[ $rc == "$want" ]] || fail "expected exit $want, got $rc: $(<"$work/output")"
}

printf 'servers: []\n' > "$repo/config/clean.yaml"
printf 'const T: &str = "%s";\n' "$token_a" > "$repo/tests/fixture.rs"
ln -s "/run/secrets/$token_a" "$repo/tests/fixture-link"
git -C "$repo" add -A
expect_rc 0

# Contents: every matching line is named, the value never is.
printf 'a: 1\ntoken: %s\nb: 2\nagain: %s\n' "$token_a" "$token_b" > "$repo/config/leak.yaml"
git -C "$repo" add config/leak.yaml
expect_rc 1
grep -qxF 'config/leak.yaml:2,4' "$work/output" || fail "content hit not located: $(<"$work/output")"
git -C "$repo" rm -qf config/leak.yaml

# A tracked file NAME holding two different tokens: both masked.
: > "$repo/config/${token_a}_and_${token_b}.yaml"
git -C "$repo" add config
expect_rc 1
grep -qxF 'config/dbmcp_svc_<redacted>_and_dbmcp_svc_<redacted>.yaml' "$work/output" \
  || fail "file-name hit not masked: $(<"$work/output")"
git -C "$repo" rm -qf "config/${token_a}_and_${token_b}.yaml"

# A SYMLINK TARGET: git grep never reads it, the index blob does.
ln -s "/run/secrets/$token_b" "$repo/config/link"
git -C "$repo" add config/link
expect_rc 1
grep -qxF 'config/link' "$work/output" || fail "symlink-target hit not named: $(<"$work/output")"

# A scanner that cannot run fails closed.
mkdir -p "$work/badgit"
real_git=$(command -v git)
for broken in grep cat-file ls-files; do
  cat > "$work/badgit/git" <<STUB
#!/usr/bin/env bash
for arg in "\$@"; do [[ \$arg == $broken ]] && exit 128; done
exec "$real_git" "\$@"
STUB
  chmod +x "$work/badgit/git"
  expect_rc 2 "$work/badgit:"
  grep -qF 'secret scan could not run' "$work/output" || fail "$broken failure not reported: $(<"$work/output")"
done

# A broken or missing grep fails closed, even where nothing matched: exit 1
# ("no match") is the only clean grep result. The symlink target staged here
# holds a token, so a grep failure read as clean would let it through.
mkdir -p "$work/badgrep"
for rc in 2 127; do
  printf '#!/usr/bin/env bash\nexit %s\n' "$rc" > "$work/badgrep/grep"
  chmod +x "$work/badgrep/grep"
  expect_rc 2 "$work/badgrep:"
  grep -qF 'secret scan could not run' "$work/output" || fail "grep exit $rc not reported: $(<"$work/output")"
done
git -C "$repo" rm -qf config/link
expect_rc 0

# An index whose path list alone exceeds the OS argument limit: the scan
# never puts the whole list on one command line. Index-only entries (no
# files on disk) keep this fast.
arg_max=$(getconf ARG_MAX)
empty=$(git -C "$repo" hash-object -w --stdin < /dev/null)
leak=$(printf 'token: %s\n' "$token_a" | git -C "$repo" hash-object -w --stdin)
long=$(printf 'p%.0s' {1..200})
count=$(( arg_max / 200 + 1000 ))
for (( i = 0; i < count; i++ )); do
  printf '100644 %s\tbulk/%06d-%s\n' "$empty" "$i" "$long"
done | git -C "$repo" update-index --index-info
expect_rc 0
printf '100644 %s\tzz/leak.yaml\n' "$leak" | git -C "$repo" update-index --index-info
expect_rc 1
grep -qxF 'zz/leak.yaml:1' "$work/output" || fail "token in the last batch not found: $(<"$work/output")"

echo 'ok: bin/secret-scan'
