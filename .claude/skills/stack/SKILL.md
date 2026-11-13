---
description: Bring up the local Postgres, Mongo and MySQL stack the gateway and its tests run against. Use for dev stack, bin/dev, state db, target db, mongo.
applies: [rust]
---

> House skill — written from this repo's own evidence and owned by this repository's maintainers. Correct it in place; setup never overwrites a skill that exists.

1. Bring the stack up: `bin/dev up` — it runs `docker compose -f docker-compose.dev.yml up -d --wait` and starts state-db (localhost:5433), target-db (localhost:5434), target-mongo (localhost:27018) and permissions-mysql (localhost:3307). fail -> a container never became healthy: `docker compose -f docker-compose.dev.yml ps` then `docker compose -f docker-compose.dev.yml logs <service>`.
2. Confirm health: `docker compose -f docker-compose.dev.yml ps` must show every service `healthy`. The integration tests hard-code these ports; changing them means changing the fallback URLs in `tests/*.rs`.
3. Run the suite against it: `bin/test` (it always runs `docker compose -f docker-compose.dev.yml up -d --wait` first — even when the stack is already up — and waits for all four services to become healthy; a service that never becomes healthy returns 75 without running cargo) or one file with `bin/test --test run_query_e2e`.
4. Inspect a database by hand: `bin/dev psql state` (gateway state — sessions, audit_calls) or `bin/dev psql target` (the example target DB).
5. Stop the stack without losing data: `bin/dev down` removes the containers, the volumes stay. Only `docker compose -f docker-compose.dev.yml down -v` wipes the volumes, and only when a test needs a virgin database.
6. Boot the gateway against it: write the minimal config from `website/docs/deployment/quickstart.md` §"Run it locally" to `config/local.yaml` (gitignored) — one server on `localhost:5434`, `tls: insecure`, `password: ${ENV:TARGET_DB_PASSWORD}` — then `TLS_DISABLED=true cargo run -- --config config/local.yaml`. fail -> the log never shows "state DB connected, migrations applied", so the state-DB migration failed; check `bin/dev psql state`.
7. Smoke the endpoint: `curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8443/mcp -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'` — `401` means the MCP endpoint and the auth gate are live; anything else means the process is not serving.
