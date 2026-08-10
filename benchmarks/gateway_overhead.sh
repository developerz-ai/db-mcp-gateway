#!/usr/bin/env bash
# benchmarks/gateway_overhead.sh — measure what the gateway adds over talking
# to the same Postgres directly, from this host, at this moment.
#
#   ./benchmarks/gateway_overhead.sh [--queries N] [--concurrent N] [--warmup N]
#
# Brings up the dev stack if it is not already running, boots a release build
# of the real gateway against benchmarks/gateway.bench.yaml, runs the harness,
# then tears down everything it started. Anything already running when this
# script starts is left alone.
#
# Requires: docker, cargo. Nothing else — no k6, no wrk.
set -euo pipefail

cd "$(dirname "$0")/.."

QUERIES=2000
CONCURRENT=8
WARMUP=200
OUT="benchmarks/results/latest.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --queries)    QUERIES="$2"; shift 2 ;;
    --concurrent) CONCURRENT="$2"; shift 2 ;;
    --warmup)     WARMUP="$2"; shift 2 ;;
    --out)        OUT="$2"; shift 2 ;;
    --database)   # accepted for CLI compatibility; postgres is the only adapter
                  [[ "$2" == "postgres" || "$2" == "postgresql" ]] || {
                    echo "only postgres is supported (see benchmarks/README.md)" >&2; exit 2; }
                  shift 2 ;;
    -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

STACK_WAS_UP=0
GATEWAY_PID=""

cleanup() {
  local status=$?
  if [[ -n "$GATEWAY_PID" ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
  fi
  # Only tear down what we brought up. A dev stack that was already running
  # belongs to whoever started it.
  if [[ "$STACK_WAS_UP" -eq 0 ]]; then
    echo "-- tearing down the dev stack this run started"
    bin/dev down >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if docker compose -f docker-compose.dev.yml ps --status running 2>/dev/null | grep -q state-db; then
  STACK_WAS_UP=1
  echo "-- dev stack already running, leaving it up afterwards"
else
  echo "-- starting dev stack"
  bin/dev up >/dev/null
fi

echo "-- waiting for Postgres"
for _ in $(seq 1 60); do
  if docker compose -f docker-compose.dev.yml exec -T target-db \
       pg_isready -U app -d app >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Minted per run and never written to disk. A benchmark has no reason to hold
# a durable credential.
export SERVICE_TOKEN_BENCH="dbmcp_svc_$(openssl rand -hex 32)"
# The gateway refuses to boot on a weak or committed signing key. The benchmark
# never mints a session JWT — it authenticates with the service token — but the
# key is still required at boot, so generate a throwaway one per run.
export SESSION_SIGNING_KEY="$(openssl rand -hex 32)"
export STATE_DB_URL="${STATE_DB_URL:-postgres://gateway:gateway-dev-only@localhost:5433/gateway}"
export BENCH_DIRECT_URL="${BENCH_DIRECT_URL:-postgres://app:app-dev-only@localhost:5434/app}"
export GATEWAY_BIND="127.0.0.1:8899"
export TLS_DISABLED=1
export BENCH_GATEWAY_URL="http://127.0.0.1:8899"
export BENCH_SERVICE_TOKEN="$SERVICE_TOKEN_BENCH"
# Quiet: per-request span logging would be measured as gateway latency.
export RUST_LOG="${RUST_LOG:-warn}"

echo "-- building release gateway + harness"
cargo build --release --quiet
cargo build --release --quiet --features bench-harness --bin bench-harness

echo "-- booting gateway"
./target/release/db-mcp-gateway --config benchmarks/gateway.bench.yaml &
GATEWAY_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:8899/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    echo "gateway exited during boot" >&2; exit 1
  fi
  sleep 1
done

echo "-- measuring (queries=$QUERIES concurrent=$CONCURRENT warmup=$WARMUP)"
./target/release/bench-harness \
  --queries "$QUERIES" \
  --concurrent "$CONCURRENT" \
  --warmup "$WARMUP" \
  --out "$OUT"
