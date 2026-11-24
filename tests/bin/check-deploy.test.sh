#!/usr/bin/env bash
# bin/check-deploy: runs promtool (rules + rule tests), helm lint, the chart's
# refusals and kubeconform (on the rendered chart and the kustomize base)
# through digest-pinned images, deploy/ mounted read-only; a failing stage
# fails the run before the next one; a refused value that renders, or fails
# outside the chart's own check, fails the run; no Docker is exit 75. Docker
# is a stub: the real run is CI's `deploy` job.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

mkdir -p "$work/repo/bin" "$work/tools"
cp bin/check-deploy "$work/repo/bin/"
for tool in bash dirname mktemp rm grep cat; do
  ln -s "$(command -v "$tool")" "$work/tools/$tool"
done
cat > "$work/tools/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CALLS"
[[ -n ${FAIL_ON:-} && $* == *"$FAIL_ON"* ]] && exit 3
if [[ $* == *' --set '* ]]; then
  [[ -n ${RENDERS:-} ]] && exit 0
  echo "${REFUSAL:-Error: execution error at (db-mcp-gateway/templates/x.yaml:1:1): refused}" >&2
  exit 1
fi
[[ $* == *' template '* || $* == *' kustomize '* ]] && echo 'kind: Service'
exit 0
STUB
chmod +x "$work/tools/docker"

check() {
  : > "$work/calls"
  (cd "$work/repo" && env -i PATH="$work/tools" CALLS="$work/calls" ${FAIL_ON:+FAIL_ON="$FAIL_ON"} \
    ${RENDERS:+RENDERS=1} ${REFUSAL:+REFUSAL="$REFUSAL"} bash bin/check-deploy) > "$work/out" 2>&1
}

check || fail "bin/check-deploy failed: $(<"$work/out")"
[[ $(wc -l < "$work/calls") == 10 ]] || fail "expected 10 docker runs: $(<"$work/calls")"
while IFS= read -r call; do
  [[ $call =~ \ [^\ ]+:[^\ ]+@sha256:[0-9a-f]{64}( |$) ]] || fail "image not pinned by digest: $call"
  [[ $call == *kubeconform* || $call == *'/deploy:ro '* ]] || fail "deploy/ not mounted read-only: $call"
done < "$work/calls"
for stage in 'promtool prom/prometheus' '-w /deploy/prometheus --entrypoint promtool' 'test rules rules.test.yaml' \
  '--set networkPolicy.ingress.gatewayFrom=null' '--set networkPolicy.ingress.gatewayFrom=all' '--set tls.certManager.dnsNames=null' 'lint --strict /deploy/helm/db-mcp-gateway -f /deploy/helm/db-mcp-gateway/ci/full-values.yaml' \
  'template db-mcp-gateway' 'kustomize /deploy/kustomize/base' '-strict'; do
  grep -qF -- "$stage" "$work/calls" || fail "missing stage '$stage': $(<"$work/calls")"
done

rc=0; FAIL_ON='lint --strict' check || rc=$?
[[ $rc == 3 ]] || fail "failing helm lint exited $rc"
! grep -q template "$work/calls" || fail 'a stage ran after helm lint failed'

rc=0; RENDERS=1 check || rc=$?
[[ $rc == 1 ]] || fail "a refused value that rendered exited $rc"
grep -qF 'must refuse it' "$work/out" || fail 'a refused value that rendered was not reported'
rc=0; REFUSAL='Error: unknown flag' check || rc=$?
[[ $rc == 1 ]] || fail "an unrelated render failure exited $rc"
grep -qF "not in the chart's own check" "$work/out" || fail 'an unrelated render failure was not reported'
! grep -q kubeconform "$work/calls" || fail 'kubeconform ran after a refusal check failed'

rm "$work/tools/docker"
rc=0; check || rc=$?
[[ $rc == 75 ]] || fail "no docker exited $rc, want 75"

echo 'ok: bin/check-deploy'
