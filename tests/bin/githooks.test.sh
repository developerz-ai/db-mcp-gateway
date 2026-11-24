#!/usr/bin/env bash
# .githooks: pre-commit refuses a staged service-token value (naming the file,
# never echoing the token) outside the exempt paths, and stays fast — no
# compile, no containers. pre-push runs clippy then the unit loop.
set -euo pipefail

# CI runners have no git identity; the scratch commits below need one.
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
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

# A token early in a large diff: grep matches and exits at once. Piped under
# pipefail, git then dies of SIGPIPE and the match read as a clean scan.
{ printf 'token: %s\n' "$token"; seq 1 400000 | sed 's/^/line: /'; } > "$repo/config/big.yaml"
git -C "$repo" add config/big.yaml
if hook pre-commit; then fail 'token at the head of a large diff accepted (SIGPIPE)'; fi
grep -qxF 'config/big.yaml' "$work/output" || fail 'large-diff refusal does not name the file'
git -C "$repo" rm -q --cached config/big.yaml

# A token in a file *name* is refused and redacted in the report.
: > "$repo/config/$token.yaml"
git -C "$repo" add "config/$token.yaml"
if hook pre-commit; then fail 'token in a staged file name accepted'; fi
grep -qxF 'config/dbmcp_svc_<redacted>.yaml' "$work/output" || fail "file name not redacted: $(<"$work/output")"
! grep -qF "$token" "$work/output" || fail 'refusal echoed the token from a file name'
git -C "$repo" rm -q --cached "config/$token.yaml"
rm "$repo/config/$token.yaml"

# A binary file's patch has no added lines: the staged blob is scanned as bytes.
printf '\0\001bin\0%s\0' "$token" > "$repo/config/blob.bin"
git -C "$repo" add config/blob.bin
if hook pre-commit; then fail 'token inside a staged binary file accepted'; fi
grep -qxF 'config/blob.bin' "$work/output" || fail "binary refusal does not name the file: $(<"$work/output")"
! grep -qF "$token" "$work/output" || fail 'binary refusal echoed the token'
git -C "$repo" rm -q --cached config/blob.bin

newline_name=$'config/new\nline.bin'
printf '\0%s\0' "$token" > "$repo/$newline_name"
git -C "$repo" add "$newline_name"
if hook pre-commit; then fail 'token in newline-named binary file accepted'; fi
grep -qF 'staged change adds a service-token' "$work/output" || fail 'newline filename scan failed instead of detecting token'
git -C "$repo" rm -q --cached "$newline_name"

# Cleaning up a leak commits: deleting a file whose name (or content) holds a
# token, or renaming it to a clean name, stages nothing to scan. Renaming a
# clean file to a token name is refused.
git -C "$repo" commit -q --no-verify -m base
printf 'x\n' > "$repo/config/$token.yaml"
printf 'token: %s\n' "$token" > "$repo/config/leaked.yaml"
printf 'clean\n' > "$repo/config/plain.yaml"
git -C "$repo" add config
git -C "$repo" commit -q --no-verify -m leak
git -C "$repo" rm -q "config/$token.yaml" config/leaked.yaml
hook pre-commit || fail "deleting leaked files refused: $(<"$work/output")"
git -C "$repo" reset -q --hard
git -C "$repo" mv "config/$token.yaml" config/renamed.yaml
hook pre-commit || fail "renaming a leaked name away refused: $(<"$work/output")"
git -C "$repo" reset -q --hard
git -C "$repo" mv config/plain.yaml "config/new-$token.yaml"
if hook pre-commit; then fail 'renaming to a token name accepted'; fi
grep -qxF 'config/new-dbmcp_svc_<redacted>.yaml' "$work/output" || fail "rename target not named: $(<"$work/output")"
git -C "$repo" reset -q --hard
git -C "$repo" rm -q "config/$token.yaml" config/leaked.yaml
git -C "$repo" commit -q --no-verify -m cleanup

# A newline inside a staged file name stays one path: split, its halves are
# pathspecs that match nothing and the blob is never scanned.
nl_name=$'config/a\nb.yaml'
printf 'token: %s\n' "$token" > "$repo/$nl_name"
git -C "$repo" add "$nl_name"
if hook pre-commit; then fail 'token in a file whose name holds a newline accepted'; fi
! grep -qF "$token" "$work/output" || fail 'newline-name refusal echoed the token'
git -C "$repo" rm -q --cached "$nl_name"
rm "$repo/$nl_name"

# A scanner that errors is a refusal, never a clean pass.
mkdir -p "$work/badgit"
real_git=$(command -v git)
cat > "$work/badgit/git" <<STUB
#!/usr/bin/env bash
for arg in "\$@"; do [[ \$arg == grep ]] && exit 2; done
exec "$real_git" "\$@"
STUB
chmod +x "$work/badgit/git"
printf 'clean: true\n' > "$repo/config/scanned.yaml"
git -C "$repo" add config/scanned.yaml
if (cd "$repo" && PATH="$work/badgit:$work/tools:$PATH" CALLS="$work/calls" bash .githooks/pre-commit) > "$work/output" 2>&1; then
  fail 'a failing scanner was read as a clean scan'
fi
grep -qF 'secret scan could not run' "$work/output" || fail "scanner error not reported: $(<"$work/output")"
git -C "$repo" rm -q --cached config/scanned.yaml

# ShellCheck sees shell scripts only: `*.sh` and the extensionless wrappers,
# never a SQL file under bin/.
cat > "$work/tools/shellcheck" <<'STUB'
#!/usr/bin/env bash
printf 'shellcheck %s\n' "$*" >> "$CALLS"
STUB
chmod +x "$work/tools/shellcheck"
mkdir -p "$repo/bin/lib"
printf -- '-- sql\n' > "$repo/bin/lib/role.sql"
printf '#!/usr/bin/env bash\n' > "$repo/bin/lib/q.sh"
printf '#!/usr/bin/env bash\n' > "$repo/bin/wrapper"
git -C "$repo" add bin
hook pre-commit || fail "shell scripts refused: $(<"$work/output")"
grep -qxF 'shellcheck -x -- bin/lib/q.sh bin/wrapper' "$work/calls" \
  || fail "shellcheck got the wrong files: $(<"$work/calls")"
git -C "$repo" rm -q --cached -r bin
rm -rf "$repo/bin/lib" "$repo/bin/wrapper"
rm "$work/tools/shellcheck"

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
