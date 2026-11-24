#!/usr/bin/env bash
# Isolated tests for bin/setup: every external tool is a stub recording its
# calls. Pins: the non-Debian path checks instead of installing, a failed
# stage shows the log's tail, prebuilt nextest before compiling it, cargo-audit
# installed, and git hooks only on --hooks.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

fixture() {
  rm -rf "${work:?}/repo" "${work:?}/tools" "${work:?}/home"
  mkdir -p "$work/repo/bin" "$work/tools" "$work/home/.cargo/bin"
  cp bin/setup "$work/repo/bin/"
  for tool in bash dirname mkdir tail; do
    ln -s "$(command -v "$tool")" "$work/tools/$tool"
  done
  cat > "$work/tools/stub" <<'STUB'
#!/usr/bin/env bash
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$CALLS"
case "$name $*" in
  'uname -s') echo Linux ;;
  'uname -m') echo x86_64 ;;
  'curl '*) echo 'tarball-bytes' ;;
  'tar '*) cat > /dev/null ;;
esac
if [[ "$name $*" == "${FAIL_AT:-}" ]]; then
  echo 'simulated failure detail'
  exit 42
fi
STUB
  chmod +x "$work/tools/stub"
  for tool in cargo docker git cc make openssl curl tar uname cat; do
    ln -s stub "$work/tools/$tool"
  done
  : > "$work/calls"
}

setup() {
  (cd "$work/repo" && env -i PATH="$work/tools" HOME="$work/home" CALLS="$work/calls" "${env[@]}" bash bin/setup "$@") \
    > "$work/output" 2>&1
}
env=()
called() { grep -qxF -- "$1" "$work/calls" || { cat "$work/calls" >&2; fail "missing call: $1"; }; }
not_called() { ! grep -qF -- "$1" "$work/calls" || fail "unexpected call: $1"; }

# Non-Debian host (no dpkg): no package manager is driven; nextest comes from
# its release tarball (no cargo-binstall), cargo-audit from cargo install.
fixture
setup || fail "setup failed: $(<"$work/output")"
grep -qF 'non-Debian host' "$work/output" || fail 'non-Debian path not announced'
called 'curl -fsSL https://get.nexte.st/0.9.151/linux'
not_called 'cargo install --locked cargo-nextest'
called 'cargo install --locked cargo-audit@0.23.0'
called 'cargo fetch --locked'
called 'docker compose -f docker-compose.dev.yml up -d --wait'
not_called 'git config'
grep -qF 'bin/setup --hooks' "$work/output" || fail 'hooks opt-in hint missing'

# cargo-binstall present: both tools come prebuilt from it.
fixture
ln -s stub "$work/tools/cargo-binstall"
setup || fail 'setup with binstall failed'
called 'cargo binstall --no-confirm --locked cargo-nextest@0.9.151'
called 'cargo binstall --no-confirm --locked cargo-audit@0.23.0'
not_called 'curl'

# Already installed: nothing reinstalled. --hooks sets core.hooksPath.
fixture
ln -s stub "$work/tools/cargo-nextest"
ln -s stub "$work/tools/cargo-audit"
setup --hooks || fail 'setup --hooks failed'
not_called 'install'
called 'git config core.hooksPath .githooks'

# Non-Debian and a tool missing: named, nothing installed.
fixture
rm "$work/tools/make"
if setup; then fail 'missing make accepted'; fi
grep -qF "'make' is missing" "$work/output" || fail 'missing tool not named'
not_called 'cargo fetch'

# A failed stage prints its message and the log tail; the log is 0600.
fixture
env=(FAIL_AT='cargo fetch --locked')
if setup; then fail 'failed fetch accepted'; fi
env=()
grep -qF 'Locked dependency fetch failed' "$work/output" || fail 'stage message missing'
grep -qF 'simulated failure detail' "$work/output" || fail 'log tail not shown'
[[ $(stat -c %a "$work/repo/target/setup.log") == 600 ]] || fail 'setup.log is not 0600'
not_called 'docker compose -f docker-compose.dev.yml up'

# Unknown flag: usage, exit 2.
fixture
rc=0; setup --bogus || rc=$?
[[ $rc == 2 ]] || fail "unknown flag exited $rc"

echo 'ok: bin/setup'
