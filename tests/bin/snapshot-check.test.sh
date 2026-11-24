#!/usr/bin/env bash
# bin/snapshot-check: the snapshot is HEAD plus exactly the listed files (an
# unlisted working-tree edit stays out, a listed deleted file is removed),
# paths resolve from the caller's directory or as absolute paths inside the
# repo, the command runs in the snapshot with its own CARGO_TARGET_DIR, and a
# path outside the repo or a missing file list is a usage error.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

repo=$work/repo
mkdir -p "$repo/bin" "$repo/src/sub" "$work/tools"
cp bin/snapshot-check "$repo/bin/"
cp -r bin/lib "$repo/bin/"
printf '#!/usr/bin/env bash\n{ printf "%%s %%s\\n" "${0##*/}" "$*"; echo "cwd=$PWD target=$CARGO_TARGET_DIR"; } >> "$CALLS"\n' \
  > "$work/tools/cargo"
chmod +x "$work/tools/cargo"

git_() { git -C "$repo" -c user.name=t -c user.email=t@example.invalid "$@"; }
git_ init -q
printf 'target/\n' > "$repo/.gitignore"
for f in mine theirs gone sub/nested; do echo committed > "$repo/src/$f.rs"; done
git_ add -A && git_ commit -qm base
for f in mine theirs sub/nested; do echo edited > "$repo/src/$f.rs"; done
echo fresh > "$repo/src/new.rs"
rm "$repo/src/gone.rs"

snap() {
  : > "$work/calls"
  (cd "$repo/${DIR:-}" && PATH="$work/tools:$PATH" CALLS="$work/calls" DBMCP_NO_QUEUE=1 \
    bash "$repo/bin/snapshot-check" "$@") > "$work/out" 2>&1
}
tree=$repo/target/snapshot/default/tree

snap src/mine.rs "$repo/src/new.rs" src/gone.rs || fail "snapshot-check failed: $(<"$work/out")"
[[ $(<"$tree/src/mine.rs") == edited ]] || fail 'listed file not overlaid'
[[ $(<"$tree/src/theirs.rs") == committed ]] || fail "an unlisted edit leaked into the snapshot"
[[ $(<"$tree/src/new.rs") == fresh ]] || fail 'listed untracked file (absolute path) missing'
[[ ! -e $tree/src/gone.rs ]] || fail 'listed deleted file still in the snapshot'
want="cargo clippy --all-targets --all-features -- -D warnings
cwd=$tree target=$repo/target/snapshot/default/target
cargo test --lib --bins --test it_offline --all-features
cwd=$tree target=$repo/target/snapshot/default/target"
[[ $(<"$work/calls") == "$want" ]] || fail "unexpected default commands: $(<"$work/calls")"

DIR=src snap --slot b sub/nested.rs -- cargo check --lib || fail "relative path from a subdir failed: $(<"$work/out")"
[[ $(<"$repo/target/snapshot/b/tree/src/sub/nested.rs") == edited ]] || fail 'subdir-relative path not resolved'
[[ $(head -1 "$work/calls") == 'cargo check --lib' ]] || fail "custom command not run: $(<"$work/calls")"
[[ $(<"$tree/src/mine.rs") == edited ]] || fail 'another slot touched the default slot'

for bad in '../outside.rs' '/etc/passwd' 'src/../../x.rs'; do
  rc=0; snap "$bad" || rc=$?
  [[ $rc == 2 && ! -s $work/calls ]] || fail "'$bad' exited $rc or ran cargo"
done
for usage in '' '-- cargo check' '--slot' '--slot a/b x.rs' 'x.rs --'; do
  rc=0
  # shellcheck disable=SC2086
  snap $usage || rc=$?
  [[ $rc == 2 && ! -s $work/calls ]] || fail "usage '$usage' exited $rc"
done

echo 'ok: bin/snapshot-check'
