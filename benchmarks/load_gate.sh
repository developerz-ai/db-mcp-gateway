#!/usr/bin/env bash
# benchmarks/load_gate.sh — fail when a harness run regressed against a stored
# baseline taken on the same runner class.
#
#   ./benchmarks/load_gate.sh RESULT.json BASELINE.json
#
# Gates per shape on what the gateway ADDS, not on absolute latency: the
# overhead deltas (gateway minus direct, p50 and p95) subtract most of the
# host's own speed, and the gateway's peak RSS. Any gateway error fails.
# A shape whose two direct baselines disagree by more than MAX_DRIFT_PCT was
# measured on a noisy host: it is reported as inconclusive and not gated —
# but a run with no conclusive shape at all fails, so a permanently noisy
# runner cannot pass silently.
#
# Tunables (env): TOLERANCE_PCT (default 50) — allowed growth over baseline;
# MAX_DRIFT_PCT (default 25). Requires jq.
set -euo pipefail

RESULT=${1:?usage: load_gate.sh RESULT.json BASELINE.json}
BASELINE=${2:?usage: load_gate.sh RESULT.json BASELINE.json}
TOLERANCE_PCT=${TOLERANCE_PCT:-50}
MAX_DRIFT_PCT=${MAX_DRIFT_PCT:-25}

# One line per shape: shape, verdict, detail. jq does the arithmetic so the
# comparison has exactly one definition.
verdicts=$(jq -r \
  --slurpfile base "$BASELINE" \
  --argjson tol "$TOLERANCE_PCT" \
  --argjson drift "$MAX_DRIFT_PCT" '
  ($base[0].measurements | map({key: .shape, value: .}) | from_entries) as $b
  | .measurements[]
  | . as $m
  | ($b[$m.shape]) as $old
  | (1 + $tol / 100) as $limit
  | if $old == null then "\($m.shape)\tnew\tno baseline for this shape"
    elif $m.gateway_errors > 0 then "\($m.shape)\tfail\t\($m.gateway_errors) gateway errors"
    elif ($m.baseline_drift_pct | fabs) > $drift then
      "\($m.shape)\tinconclusive\tdirect baselines drifted \($m.baseline_drift_pct | floor)%"
    else
      [ ["p50 overhead ms", $m.overhead.p50_delta_ms, $old.overhead.p50_delta_ms],
        ["p95 overhead ms", $m.overhead.p95_delta_ms, $old.overhead.p95_delta_ms],
        ["peak RSS bytes", $m.gateway_resources.peak_rss_bytes,
                           $old.gateway_resources.peak_rss_bytes] ]
      | map(select(.[2] > 0 and .[1] > .[2] * $limit))
      | if length == 0 then "\($m.shape)\tpass\twithin \($tol)% of baseline"
        else "\($m.shape)\tfail\t" + (map("\(.[0]) \(.[1]) > \(.[2]) +\($tol)%") | join("; "))
        end
    end
' "$RESULT")

echo "| shape | verdict | detail |"
echo "|---|---|---|"
while IFS=$'\t' read -r shape verdict detail; do
  echo "| ${shape} | ${verdict} | ${detail} |"
done <<<"$verdicts"

if grep -q $'\tfail\t' <<<"$verdicts"; then
  echo "load gate: regression against $BASELINE" >&2
  exit 1
fi
if ! grep -qE $'\t(pass|new)\t' <<<"$verdicts"; then
  echo "load gate: no conclusive measurement — every shape drifted" >&2
  exit 1
fi
