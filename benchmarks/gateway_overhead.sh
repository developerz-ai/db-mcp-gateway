#!/usr/bin/env bash
# benchmarks/gateway_overhead.sh — measure what the gateway adds over talking
# to the same database directly, from this host, at this moment.
#
#   ./benchmarks/gateway_overhead.sh [--backend postgres|mongo] [--queries N]
#       [--concurrent N] [--warmup N] [--instances N] [--mysql-rejection]
#       [--resource-sample-ms N] [--db-name NAME] [--out PATH]
#
# Brings up the dev stack if it is not already running, boots a release build
# of the real gateway against benchmarks/gateway.bench.yaml, runs the harness,
# then tears down everything it started. Anything already running when this
# script starts is left alone.
#
# `--backend mongo` measures the same comparison against the `target-mongo`
# container instead of `target-db`; the query goes through the gateway's mongo
# adapter, which is read-only by construction (src/exec/mongo/rejector.rs).
#
# `--instances N` boots N gateway processes and spreads the load across them.
# On one host that measures contention between the instances, NOT horizontal
# scaling — the load generator, the gateways and the database all share the
# same cores. The harness labels it as such.
#
# `--mysql-rejection` adds a check that the gateway refuses a `kind: mysql`
# query target at boot (there is no mysql query adapter). It is reported in
# its own section, never mixed into the performance numbers.
#
# `--database` keeps its legacy meaning: a backend selector, accepting only
# `postgres` or `postgresql`, and selecting the postgres measurement. The
# database NAME is `--db-name`. `--database` used to name the database and
# now means the engine again — a name silently becoming a selector is how
# `--database postgres` ended up pointing at a database that does not exist.
#
# Requires: docker, cargo, curl, openssl. Nothing else — no k6, no wrk.
set -euo pipefail

cd "$(dirname "$0")/.."

QUERIES=2000
CONCURRENT=8
WARMUP=200
OUT="benchmarks/results/latest.json"
BACKEND=postgres
# Set when the legacy `--database` selector was used, so a conflict with
# `--backend` can be reported instead of silently picking one.
BACKEND_SET=""
INSTANCES=1
DB_NAME=app
RESOURCE_SAMPLE_MS=1000
MYSQL_REJECTION=0

# The bench YAML declares both targets; the harness picks the one it measures
# via `--server`.
SERVER_TARGET="target"
SERVER_MONGO="mongo"

# Base port for the first gateway instance; instance i binds base+i.
GATEWAY_BASE_PORT=8899

# Config declaring a `kind: mysql` query target. Never booted as a working
# target — it exists so the harness can prove the boot-time rejection.
MYSQL_REJECTION_CONFIG="benchmarks/gateway.bench.mysql.yaml"

COMPOSE=(docker compose -f docker-compose.dev.yml)

usage() {
  cat <<'EOF'
benchmarks/gateway_overhead.sh — measure what the gateway adds over talking to
the same database directly, from this host, at this moment.

Usage:
  ./benchmarks/gateway_overhead.sh [options]

Options:
  --backend postgres|mongo  Engine to measure (default: postgres)
  --queries N               Measured requests per path, per shape (default: 2000)
  --concurrent N            Concurrent in-flight requests (default: 8)
  --warmup N                Requests discarded before measuring (default: 200)
  --instances N             Gateway instances to boot and spread load over
                            (default: 1). On one host this measures contention,
                            not horizontal scaling.
  --db-name NAME            Database name for the measured request (default:
                            app). Only `app` is supported — the database the
                            dev stack provisions and the bench config grants;
                            any other name exits 2 before the stack starts
  --database postgres|postgresql
                            Legacy alias for `--backend postgres`; picks the
                            postgres target. Not a database name.
  --out PATH                Where to write the raw JSON result
                            (default: benchmarks/results/latest.json)
  --resource-sample-ms N    Interval between gateway resource samples
                            (default: 1000)
  --mysql-rejection         Also verify that a `kind: mysql` query target is
                            refused at boot, reported in its own section
  -h, --help                Print this help and exit

Backends:
  postgres  target-db    localhost:5434  database `app`  server `target`
  mongo     target-mongo localhost:27018 database `app`  server `mongo`

Requires: docker, cargo, curl, openssl. Nothing else — no k6, no wrk.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --queries)    QUERIES="$2"; shift 2 ;;
    --concurrent) CONCURRENT="$2"; shift 2 ;;
    --warmup)     WARMUP="$2"; shift 2 ;;
    --out)        OUT="$2"; shift 2 ;;
    --db-name)
      [[ $# -ge 2 ]] || { echo "--db-name needs a value" >&2; exit 2; }
      DB_NAME="$2"; shift 2 ;;
    --instances)  INSTANCES="$2"; shift 2 ;;
    --resource-sample-ms) RESOURCE_SAMPLE_MS="$2"; shift 2 ;;
    --database)
      [[ $# -ge 2 ]] || { echo "--database needs a value" >&2; exit 2; }
      # Legacy meaning: a backend selector, not a database name. It accepted
      # only postgres spellings and exited 2 on anything else — kept here so
      # the flag that used to work still works, and still fails loudly on a
      # value it never accepted.
      case "$2" in
        postgres|postgresql)
          if [[ -n "$BACKEND_SET" && "$BACKEND" != "postgres" ]]; then
            echo "--database selects postgres but --backend $BACKEND was requested" >&2
            exit 2
          fi
          BACKEND=postgres
          BACKEND_SET="--database"
          ;;
        *)
          echo "--database must be postgres or postgresql (got: $2)" >&2
          exit 2
          ;;
      esac
      shift 2 ;;
    --backend)
      case "$2" in
        postgres|mongo) BACKEND="$2" ;;
        *) echo "--backend must be postgres or mongo (got: $2)" >&2; exit 2 ;;
      esac
      if [[ -n "$BACKEND_SET" && "$BACKEND_SET" != "--backend" && "$BACKEND" != "postgres" ]]; then
        echo "--backend $BACKEND conflicts with $BACKEND_SET (postgres)" >&2
        exit 2
      fi
      BACKEND_SET="--backend"
      shift 2 ;;
    --mysql-rejection) MYSQL_REJECTION=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if ! [[ "$INSTANCES" =~ ^[1-9][0-9]*$ ]]; then
  echo "--instances must be a positive integer (got: $INSTANCES)" >&2
  exit 2
fi
if ! [[ "$QUERIES" =~ ^[0-9]+$ ]] || ! [[ "$CONCURRENT" =~ ^[0-9]+$ ]] \
   || ! [[ "$WARMUP" =~ ^[0-9]+$ ]] || ! [[ "$RESOURCE_SAMPLE_MS" =~ ^[0-9]+$ ]]; then
  echo "--queries/--concurrent/--warmup/--resource-sample-ms must be integers" >&2
  exit 2
fi

# Only the database the dev stack provisions is supported. The bench gateway
# config declares and grants exactly one database per target (`app`), the
# direct baseline URLs name the same one, and the containers are bootstrapped
# with it. Another name would be seeded and only then refused — by the
# gateway's grants, or by the harness's database-match guard — after the
# whole stack had been brought up. Reject it here, before anything starts.
if [[ "$DB_NAME" != "app" ]]; then
  echo "--db-name must be app — the only database the dev stack provisions (got: $DB_NAME)" >&2
  exit 2
fi

if [[ "$BACKEND" == "mongo" ]]; then
  SERVER="$SERVER_MONGO"
else
  SERVER="$SERVER_TARGET"
fi

STACK_WAS_UP=0
MONGO_STARTED_BY_US=0
GATEWAY_PIDS=()

cleanup() {
  local status=$?
  local pid
  for pid in ${GATEWAY_PIDS[@]+"${GATEWAY_PIDS[@]}"}; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  # Only tear down what we brought up. A dev stack that was already running
  # belongs to whoever started it.
  if [[ "$STACK_WAS_UP" -eq 0 ]]; then
    echo "-- tearing down the dev stack this run started"
    bin/dev down >/dev/null 2>&1 || true
  elif [[ "$MONGO_STARTED_BY_US" -eq 1 ]]; then
    # The stack was already up but the mongo container was not part of it.
    # Stop just that container — the rest of the stack is not ours.
    echo "-- stopping the mongo container this run started"
    "${COMPOSE[@]}" stop target-mongo >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if "${COMPOSE[@]}" ps --status running 2>/dev/null | grep -q state-db; then
  STACK_WAS_UP=1
  echo "-- dev stack already running, leaving it up afterwards"
else
  echo "-- starting dev stack"
  bin/dev up >/dev/null
fi

if [[ "$BACKEND" == "postgres" ]]; then
  echo "-- waiting for Postgres"
  postgres_ready=0
  for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T target-db \
         pg_isready -U app -d app >/dev/null 2>&1; then
      postgres_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$postgres_ready" -ne 1 ]]; then
    echo "target-db did not become ready in 60s" >&2
    exit 1
  fi
else
  # The mongo container is part of the same compose file, but a stack that was
  # already up may have been started without it. Start it if it is missing —
  # and remember that we did, so the teardown stops exactly that container.
  if ! "${COMPOSE[@]}" ps --status running 2>/dev/null | grep -q target-mongo; then
    echo "-- starting the mongo container"
    # The ownership flag is set BEFORE `up`: under `set -e`, a container that
    # starts but fails the `--wait` health check would otherwise exit here
    # with the flag unset and leak a running container past cleanup.
    MONGO_STARTED_BY_US=1 "${COMPOSE[@]}" up -d --wait target-mongo >/dev/null
  fi

  echo "-- waiting for Mongo"
  mongo_ready=0
  for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T target-mongo \
         mongosh --quiet --eval "db.adminCommand('ping').ok" >/dev/null 2>&1; then
      mongo_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$mongo_ready" -ne 1 ]]; then
    echo "target-mongo did not become ready in 60s" >&2
    exit 1
  fi
fi

# Minted per run and never written to disk. A benchmark has no reason to hold
# a durable credential.
export SERVICE_TOKEN_BENCH="dbmcp_svc_$(openssl rand -hex 32)"
# The gateway refuses to boot on a weak or committed signing key. The benchmark
# never mints a session JWT — it authenticates with the service token — but the
# key is still required at boot, so generate a throwaway one per run.
export SESSION_SIGNING_KEY="$(openssl rand -hex 32)"
export STATE_DB_URL="${STATE_DB_URL:-postgres://gateway:gateway-dev-only@localhost:5433/gateway}"
export BENCH_DIRECT_URL="${BENCH_DIRECT_URL:-postgres://app:app-dev-only@localhost:5434/app}"
# Dev credential already public in docker-compose.dev.yml — the mongo
# container's root user, verified against `admin`.
export BENCH_MONGO_DIRECT_URL="${BENCH_MONGO_DIRECT_URL:-mongodb://app:app-dev-only@localhost:27018/app}"
export TLS_DISABLED=1
# Quiet: per-request span logging would be measured as gateway latency.
export RUST_LOG="${RUST_LOG:-warn}"

echo "-- building release gateway + harness"
cargo build --release --quiet
cargo build --release --quiet --features bench-harness --bin bench-harness

GATEWAY_URLS=()
for i in $(seq 0 $((INSTANCES - 1))); do
  port=$((GATEWAY_BASE_PORT + i))
  GATEWAY_URLS+=("http://127.0.0.1:${port}")
done

# The first instance is the "gateway" the harness talks to; the full list is
# what a multi-instance run spreads the load over.
export BENCH_GATEWAY_URL="${GATEWAY_URLS[0]}"
export BENCH_SERVICE_TOKEN="$SERVICE_TOKEN_BENCH"
GATEWAY_URL_LIST="$(IFS=,; echo "${GATEWAY_URLS[*]}")"

for i in $(seq 0 $((INSTANCES - 1))); do
  port=$((GATEWAY_BASE_PORT + i))
  echo "-- booting gateway on 127.0.0.1:${port}"
  GATEWAY_BIND="127.0.0.1:${port}" \
    ./target/release/db-mcp-gateway --config benchmarks/gateway.bench.yaml &
  GATEWAY_PIDS+=($!)
done

# PID check first — an /healthz reply from a stale process on port 8899 must
# not satisfy readiness for a gateway that already exited.
#
# Wall-clock deadline (not `seq 1 60`) because `curl` without `--max-time` can
# hang on a stalled socket for far longer than one iteration, blowing past the
# advertised 60 s bound. `--connect-timeout` caps the TCP handshake, `--max-time`
# caps the whole request; a single stalled probe can no longer wedge the loop.
for i in $(seq 0 $((INSTANCES - 1))); do
  pid="${GATEWAY_PIDS[$i]}"
  port=$((GATEWAY_BASE_PORT + i))
  gateway_ready=0
  deadline=$(( $(date +%s) + 60 ))
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "gateway on port ${port} exited during boot" >&2; exit 1
    fi
    if curl -fsS --connect-timeout 2 --max-time 5 \
         "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      gateway_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$gateway_ready" -ne 1 ]]; then
    echo "gateway on port ${port} did not become ready in 60s" >&2
    exit 1
  fi
done

# Best-effort channel for the harness's resource sampler: the PIDs of the
# gateway processes this run started. The harness may also discover them from
# the listening ports; this is a convenience, not a contract.
export BENCH_GATEWAY_PIDS="$(IFS=,; echo "${GATEWAY_PIDS[*]}")"

HARNESS_ARGS=(
  --backend "$BACKEND"
  --server "$SERVER"
  --database "$DB_NAME"
  --queries "$QUERIES"
  --concurrent "$CONCURRENT"
  --warmup "$WARMUP"
  --out "$OUT"
  --instances "$INSTANCES"
  --gateway-url-list "$GATEWAY_URL_LIST"
  --resource-sample-ms "$RESOURCE_SAMPLE_MS"
)

if [[ "$BACKEND" == "mongo" ]]; then
  # The mongo baseline URL travels by environment ONLY (BENCH_MONGO_DIRECT_URL,
  # exported above — the harness's Cli declares the same env fallback). A
  # credential-bearing URL must not sit in a process argument, where `ps`
  # exposes it to every local user on the host.
  #
  # The baseline names the same database as the gateway path (`--db-name`).
  # The two paths must query one database or the comparison is meaningless,
  # and the harness refuses to run when they disagree — so the name is
  # shared rather than configured twice.
  HARNESS_ARGS+=(
    --mongo-database "$DB_NAME"
  )
fi

if [[ "$MYSQL_REJECTION" -eq 1 ]]; then
  HARNESS_ARGS+=(--mysql-rejection-config "$MYSQL_REJECTION_CONFIG")
fi

echo "-- measuring (backend=$BACKEND queries=$QUERIES concurrent=$CONCURRENT warmup=$WARMUP instances=$INSTANCES)"
./target/release/bench-harness "${HARNESS_ARGS[@]}"
