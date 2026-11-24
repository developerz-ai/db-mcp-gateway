---
description: Bring up the local dev stack (Postgres, MySQL, Mongo, Redis, Dragonfly; optional YugabyteDB and Dex) the gateway and its tests run against. Use for dev stack, bin/dev, bin/run, state db, target db, mongo, redis.
applies: [rust]
---

> House skill — written from this repo's own evidence and owned by this repository's maintainers. Correct it in place; setup never overwrites a skill that exists.

Every command goes through a `bin/` wrapper. They source `.env` (`bin/lib/dotenv.sh`), and the compiling/testing ones queue behind each other (`bin/lib/queue.sh`: a `heavy` lock for compiles, a `db` lock for the shared dev databases), so concurrent agents take turns instead of thrashing the box. Never call raw `cargo test` against a DB-backed suite (`tests/it_db/`): it skips the `db` lock and races another run on the same databases.

1. Bring the stack up: `bin/dev up` — `docker compose -f docker-compose.dev.yml up -d --wait` over the six default services: `state-db` (localhost:5433), `target-db` (:5434), `permissions-mysql` (:3307), `target-mongo` (:27018), `target-redis` (:6380), `target-dragonfly` (:6381). Ports move with the `*_PORT` variables in `.env`. Two services sit behind compose profiles and never start by default: `target-yugabyte` (profile `yugabyte`, YSQL on :5435 — `bin/test-yugabyte` starts it) and `dex` (profile `idp`, :5556 — `bin/run --idp` starts it). fail -> `bin/dev ps`, then `bin/dev logs <service>`.
2. Inspect a store by hand: `bin/dev psql state` (sessions, audit_calls, permissions), `bin/dev psql target`, `bin/dev mysql`, `bin/dev mongosh`, `bin/dev ysqlsh`.
3. Run tests against it: `bin/test --unit` needs no Docker (lib + bins + `tests/it_offline`). `bin/test` (full suite) and `bin/test --test it_db <module>::` run `compose up -d --wait` first and return 75 without running cargo when a service never becomes healthy.
4. Stop without losing data: `bin/dev down` (volumes stay). `bin/dev reset` removes the volumes — only when a test needs a virgin database.
5. Boot the gateway: `bin/run` starts `state-db` + `target-db` if they are not running, mints a dev service token once into `target/dev/service-token`, and runs `cargo run` with the committed `config/dev.yaml` (TLS off, dev-only defaults; `.env` and the shell override them). fail -> the log never shows the state DB migrations applied: check `bin/dev psql state`.
6. Seed and call it: `bin/seed` loads `examples/demo/seed.sql` into a `shop` database on `target-db` (idempotent). `bin/mcp-call --list`, then `bin/mcp-call run_query '{"server":"local","database":"shop","sql":"select 1"}'` — exit 1 on a JSON-RPC error or `isError`.
