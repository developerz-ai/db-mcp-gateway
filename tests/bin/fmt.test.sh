#!/usr/bin/env bash
# bin/fmt --changed: hands rustfmt exactly the .rs files changed since the
# merge base with origin/main (committed, staged, unstaged) plus untracked
# ones, never a deleted or ignored file, with skip_children so a listed mod.rs
# does not reformat its unlisted children. Plain bin/fmt stays `cargo fmt --all`.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

repo=$work/repo
mkdir -p "$repo/bin" "$repo/src/m" "$work/tools"
cp bin/fmt "$repo/bin/"
for tool in rustfmt cargo; do
  printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" "${0##*/}" "$*" >> "$CALLS"\n' > "$work/tools/$tool"
  chmod +x "$work/tools/$tool"
done

git_() { git -C "$repo" -c user.name=t -c user.email=t@example.invalid "$@"; }
git_ init -q
printf 'target/\n' > "$repo/.gitignore"
touch "$repo/src/main.rs" "$repo/src/m/mod.rs" "$repo/src/untouched.rs" "$repo/src/gone.rs"
git_ add -A && git_ commit -qm base
git_ update-ref refs/remotes/origin/main HEAD
echo '// committed' >> "$repo/src/m/mod.rs"
git_ commit -qam 'branch change'
echo '// unstaged' >> "$repo/src/main.rs"
rm "$repo/src/gone.rs"
mkdir -p "$repo/target" && touch "$repo/target/ignored.rs"
touch "$repo/src/new file.rs" "$repo/notes.md"

fmt() {
  : > "$work/calls"
  (cd "$repo" && PATH="$work/tools:$PATH" CALLS="$work/calls" bash bin/fmt "$@") > "$work/out" 2>&1
}

fmt --changed || fail "bin/fmt --changed failed: $(<"$work/out")"
want='rustfmt --config skip_children=true src/m/mod.rs src/main.rs src/new file.rs'
[[ $(<"$work/calls") == "$want" ]] || fail "unexpected rustfmt call: $(<"$work/calls")"

fmt --changed HEAD || fail 'explicit base failed'
want='rustfmt --config skip_children=true src/main.rs src/new file.rs'
[[ $(<"$work/calls") == "$want" ]] || fail "base HEAD: $(<"$work/calls")"

rc=0; fmt --changed no-such-ref || rc=$?
[[ $rc == 2 && ! -s $work/calls ]] || fail "unknown base exited $rc"

fmt || fail 'plain bin/fmt failed'
[[ $(<"$work/calls") == 'cargo fmt --all' ]] || fail "plain bin/fmt: $(<"$work/calls")"

rc=0; fmt --bogus || rc=$?
[[ $rc == 2 ]] || fail "unknown flag exited $rc"

echo 'ok: bin/fmt'
