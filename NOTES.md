# db-mcp-gateway

A self-hosted MCP gateway that gives AI agents audited, SSO-gated, read-only database access
without ever handing a database credential to the client. A team deploys it once; developers
point their agent's MCP config at one URL. The gateway holds every DB credential, resolves the
caller's SSO identity to a grant, enforces per-grant constraints (read-only by default, writes
opt-in), and writes a synchronous append-only audit row for every call. Tool surface includes
`list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain`, and
`get_query_history`. Permissions are config-as-code in YAML (PR-reviewed) or set via an
SSO-gated admin API.

- **Stack:** Rust (stable, edition 2024, pinned via `rust-toolchain.toml`) with tokio, axum,
  sqlx (Postgres-first), serde/YAML config, `thiserror`/`anyhow`, `tracing`. MCP is a
  hand-rolled JSON-RPC over HTTP+SSE. Postgres is the co-deployed state store. Distributed as
  a container image `ghcr.io/developerz-ai/db-mcp-gateway`, built on `v*` tags; CI runs on
  GitHub Actions/Blacksmith. A Docusaurus-style `website/` holds the docs site.
- **Key commands:** `bin/dev up` / `down` / `logs` / `psql state|target` (local stack),
  `bin/test` (unit + integration, `--test <name>` for one), `bin/fmt`, `bin/lint`
  (fmt-check + `clippy -D warnings`), `bin/ci` (reproduce CI locally),
  `cargo run -- --config config/example.yaml`, `docker build -t db-mcp-gateway:dev .`.
- **Layout:**
  - `src/transport/`, `src/auth/`, `src/authz/` — MCP framing; OIDC/JWT/sessions; grant
    evaluation and constraint merge (all security-review-required areas)
  - `src/tools/`, `src/exec/` — MCP tool dispatch; per-DB pools, timeouts, row caps, cancellation
  - `src/audit/`, `src/state/`, `src/config/` — audit writer/pruner/sinks; state DB queries;
    YAML schema, validation, secrets, hot reload
  - `migrations/` + `migrations-mysql/`, `config/example.yaml`, `bin/`, `tests/`
  - `docs/initial-idea/` (canonical spec), `docs/usage/`, `docs/deployment/`, `website/`
- **State as of 2026-07-21:** branch `main`; working tree was clean when this note was written.
  Crate version in `Cargo.toml` was 1.3.0.
