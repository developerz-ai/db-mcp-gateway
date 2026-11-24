#!/usr/bin/env bash
# bin/regen-serial: rebuilds the nextest run-alone filter from the
# serial(world) attributes in tests/it_db (sorted, it_global kept), leaves the
# rest of the config alone, and `--check` reports a stale list without writing.
# (Whether the committed config is current is it_offline::isolation_guard's.)
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

mkdir -p "$work/bin" "$work/.config" "$work/tests/it_db"
cp bin/regen-serial "$work/bin/"
cat > "$work/.config/nextest.toml" <<'TOML'
[[profile.default.overrides]]
filter = """
binary(it_global) | (binary(it_db) & (
    test(=gone::stale)
))
"""
threads-required = "num-test-threads"
test-group = "shared-db"

[[profile.default.overrides]]
filter = "kind(test)"
test-group = "shared-db"
TOML
cat > "$work/tests/it_db/sweeps.rs" <<'RS'
#[tokio::test]
#[serial_test::serial(world)]
// a comment between the attribute and the fn
async fn zeta_sweeps() {}

#[tokio::test]
#[serial_test::parallel(world)]
async fn reads() {}
RS
cat > "$work/tests/it_db/caps.rs" <<'RS'
#[serial_test::serial(world)]
#[test]
fn alpha_seeds<T>() {}
RS

rc=0
python3 -I "$work/bin/regen-serial" --check >/dev/null 2>&1 || rc=$?
[[ $rc == 1 ]] || fail "--check on a stale list exited $rc, want 1"
grep -qF 'test(=gone::stale)' "$work/.config/nextest.toml" || fail '--check wrote the config'

python3 -I "$work/bin/regen-serial" >/dev/null || fail 'regen failed'
expected='[[profile.default.overrides]]
filter = """
binary(it_global) | (binary(it_db) & (
    test(=caps::alpha_seeds)
  | test(=sweeps::zeta_sweeps)
))
"""
threads-required = "num-test-threads"
test-group = "shared-db"

[[profile.default.overrides]]
filter = "kind(test)"
test-group = "shared-db"'
[[ $(<"$work/.config/nextest.toml") == "$expected" ]] \
  || fail "unexpected config: $(<"$work/.config/nextest.toml")"
python3 -I "$work/bin/regen-serial" --check >/dev/null || fail 'regenerated config reads as stale'

rc=0
python3 -I "$work/bin/regen-serial" --bogus >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]] || fail "unknown flag exited $rc, want 2"

echo 'ok: bin/regen-serial'
