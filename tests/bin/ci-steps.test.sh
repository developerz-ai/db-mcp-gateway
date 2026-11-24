#!/usr/bin/env bash
# Runs two ci.yml step scripts verbatim (extracted from the workflow) against
# fixtures: the `changes` filter turns `msrv` on for a change to build.rs
# alone, and the `merge` job's index staging fails when `imagetools create`
# fails, even though a previous run's index tag still inspects cleanly.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# The `run: |` block of the step whose `id:` is $1, dedented.
step_script() {
  python3 -I - "$root/.github/workflows/ci.yml" "$1" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
start = next(i for i, l in enumerate(lines) if l.strip() in (f"id: {sys.argv[2]}", f"- id: {sys.argv[2]}"))
run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
indent = len(lines[run]) - len(lines[run].lstrip()) + 2
body = []
for line in lines[run + 1:]:
    if line.strip() and len(line) - len(line.lstrip()) < indent:
        break
    body.append(line[indent:])
print("\n".join(body))
PY
}

# changes: a PR touching only build.rs must run the MSRV build.
step_script diff > "$work/diff.sh"
repo=$work/repo
git init -q "$repo"
printf 'fn main() {}\n' > "$repo/build.rs"
git -C "$repo" add build.rs
git -C "$repo" commit -q -m base
printf 'fn main() { println!("cargo:rerun-if-changed=x"); }\n' > "$repo/build.rs"
git -C "$repo" commit -q -am build-script
: > "$work/out"
(cd "$repo" && GITHUB_EVENT_NAME=pull_request GITHUB_OUTPUT="$work/out" RUNNER_TEMP="$work" BEFORE='' \
  bash -e "$work/diff.sh") > /dev/null
grep -qx 'msrv=true' "$work/out" || fail "build.rs alone did not trigger msrv: $(<"$work/out")"

# merge/digest: a failed create on a rerun must not sign the old index.
step_script digest > "$work/digest.sh"
mkdir -p "$work/tools"
cat > "$work/tools/docker" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  'buildx imagetools create '*) exit 1 ;;
  'buildx imagetools inspect '*) echo '{"digest":"sha256:previous-run"}' ;;
esac
STUB
chmod +x "$work/tools/docker"
: > "$work/out"
if PATH="$work/tools:$PATH" GITHUB_OUTPUT="$work/out" SHORT=abc1234 GHCR_IMAGE=ghcr.invalid/x \
  DOCR_IMAGE=docr.invalid/x bash "$work/digest.sh" > /dev/null 2>&1; then
  fail 'a failed imagetools create was masked by inspecting the old index'
fi
! grep -q 'previous-run' "$work/out" || fail 'the old index digest reached the step outputs'

echo 'ok: ci.yml steps'
