#!/usr/bin/env bash
# .githooks/pre-commit: `git grep --cached` skips symlinks, so a staged link
# whose target holds a service-token value is scanned through its blob and
# refused (named, never echoed). A clean link, a failing blob read and a link
# under an exempt path behave like any other staged file.
set -euo pipefail

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
cd "$(dirname "$0")/../.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
token="dbmcp_svc_$(printf '%064d' 7)"

mkdir -p "$work/tools"
cat > "$work/tools/cargo" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$work/tools/cargo"

repo=$work/repo
git init -q "$repo"
mkdir -p "$repo/.githooks" "$repo/config" "$repo/tests"
cp "$root/.githooks/pre-commit" "$repo/.githooks/"

hook() {
  (cd "$repo" && PATH="${1:-}$work/tools:$PATH" bash .githooks/pre-commit) > "$work/output" 2>&1
}

ln -s "/run/secrets/$token" "$repo/config/leak-link"
git -C "$repo" add config/leak-link
if hook; then fail 'staged symlink whose target holds a token accepted'; fi
grep -qxF 'config/leak-link' "$work/output" || fail "symlink refusal does not name the link: $(<"$work/output")"
! grep -qF "$token" "$work/output" || fail 'symlink refusal echoed the token'

# The same link beside a regular leaked file: both named once.
printf 'token: %s\n' "$token" > "$repo/config/leak.yaml"
git -C "$repo" add config/leak.yaml
if hook; then fail 'symlink plus leaked file accepted'; fi
[[ $(grep -cxE 'config/leak(-link|\.yaml)' "$work/output") == 2 ]] \
  || fail "both leaks not named: $(<"$work/output")"
git -C "$repo" rm -q --cached config/leak.yaml config/leak-link

ln -s clean-target "$repo/config/clean-link"
git -C "$repo" add config/clean-link
hook || fail "clean symlink refused: $(<"$work/output")"

# A blob that cannot be read is a refusal, never a clean pass.
mkdir -p "$work/badgit"
real_git=$(command -v git)
cat > "$work/badgit/git" <<STUB
#!/usr/bin/env bash
for arg in "\$@"; do [[ \$arg == cat-file ]] && exit 128; done
exec "$real_git" "\$@"
STUB
chmod +x "$work/badgit/git"
if hook "$work/badgit:"; then fail 'a failing symlink blob read was a clean scan'; fi
grep -qF 'secret scan could not run' "$work/output" || fail "cat-file error not reported: $(<"$work/output")"
git -C "$repo" rm -q --cached config/clean-link

ln -s "/run/secrets/$token" "$repo/tests/fixture-link"
git -C "$repo" add tests/fixture-link
hook || fail "symlink under the exempt tests/ path refused: $(<"$work/output")"

echo 'ok: .githooks symlink targets'
