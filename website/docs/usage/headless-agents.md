# Headless agents: service tokens, attribution, tiers

For an agent that runs unattended — a coding-agent fleet, a devops runner, a CI job — there is no browser to finish an SSO login. It connects with a **service token** your platform team issues, and tells the gateway, per call, which run it is and who it is acting for. Humans in Claude Code use SSO instead: see [claude-code.md](claude-code.md).

## Connect

Every request carries the token as a bearer, plus two attribution headers:

```http
POST /mcp HTTP/1.1
Host: db.internal.acme.com
Authorization: Bearer dbmcp_svc_...
x-dbmcp-run-id: run-8f3c2a
x-dbmcp-on-behalf-of: alice@acme.com
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"list_servers","arguments":{}}}
```

In an MCP client config that takes static headers:

```json
{
  "mcpServers": {
    "db-gateway": {
      "type": "http",
      "url": "https://db.internal.acme.com/mcp",
      "headers": {
        "Authorization": "Bearer ${DB_GATEWAY_TOKEN}",
        "x-dbmcp-run-id": "${RUN_ID}",
        "x-dbmcp-on-behalf-of": "${REQUESTER}"
      }
    }
  }
}
```

To check what the token resolves to, call `whoami`: it answers `"auth": "service"`, the `service_account` name, its one group and the grants that group holds — no session expiry, since a service token has none.

Keep the token in your secret manager, never in a repo. It does not expire and cannot be revoked in-band — rotation is an operator config edit plus rollout ([spec 14](../initial-idea/14-service-tokens.md)).

## The two headers

| Header | What to send | Lands in |
|---|---|---|
| `x-dbmcp-run-id` | Your task / run / job id — one per agent run | `audit_calls.upstream_run_id` |
| `x-dbmcp-on-behalf-of` | The person or system the run works for | `audit_calls.upstream_actor` |

- Each value: 1–128 characters from `A-Z a-z 0-9 . _ : @ / + = -`, sent once. Anything else refuses the call with `invalid_arguments` (JSON-RPC `-32602`) — fix the header, don't retry blindly.
- They are **claims**. The gateway records and logs them; it never uses them to decide access. Access is exactly your token's permissions group, and the audit subject is always `service:<name>`.
- If your account is configured with `require_upstream: true`, a call missing either header is refused with `invalid_arguments`.
- `get_query_history` with `x-dbmcp-run-id` returns only that run's queries — runs sharing a token don't see each other's history. Leave the header off to see everything your token ran.
- SSO sessions don't need them: the headers are ignored when a human is logged in.

Each token has its own concurrency budget — 16 in-flight requests by default, or the account's `max_concurrent_requests`. Every `/mcp` answer reports it in `x-dbmcp-concurrency-limit` and `x-dbmcp-concurrency-remaining`. Past it the gateway answers `429` with `Retry-After: 1` and a JSON-RPC error (`code` `-32000`, `data.code` `concurrency_limit_exceeded`, `data.retry_after_s`); a saturated gateway answers `503` the same way with `data.code` `service_overloaded`. Back off for `retry_after_s` and retry — nothing ran and nothing was audited.

## Tiers

Your token's group decides the tier. Both tiers use the same server and database names; the difference is the database role your statements run as.

| Tier | Grant | Can | Runs as |
|---|---|---|---|
| Inspect | `schema_read` | `list_*`, `describe_schema`, `table_stats`, `db_activity` | read-only role |
| Read (coding agents) | `query_read` | the above, plus `run_query` reads, `sample_table`, `explain` (incl. `analyze: true`), `cancel_query` | read-only role, read-only transaction |
| Read + write (devops agents) | `query_write` | the above, plus single `INSERT` / `UPDATE` / `DELETE`, `dry_run`, `explain` of DML | reads: read-only role; writes: the database's write role |

A read-tier token cannot write even if the SQL guard had a bug: its statements never reach a role that holds write privileges.

## Write semantics

- **One statement per call.** A single `INSERT`, `UPDATE` or `DELETE`, committed before the response returns. No DDL, no `BEGIN`/`COMMIT`, no multi-statement bodies, no Mongo or Redis writes — those are refused `forbidden_sql`.
- **`rows_affected`** is in every write result and in the audit row. With `RETURNING`, rows past the limit are cut from the response (`truncated: true`) but the write itself is never cut short.
- **Rehearse with `dry_run: true`.** The write runs, reports `rows_affected`, and is rolled back; the response says `"dry_run": true` and the audit row's outcome is `dry_run`.

  ```json
  {"name": "run_query", "arguments": {
    "server": "prod", "database": "app",
    "sql": "UPDATE orders SET status = 'cancelled' WHERE id = 1042",
    "dry_run": true, "reason": "INC-311 stuck order"}}
  ```

- **Plan first with `explain`.** Plain `EXPLAIN` of a write never executes it. `analyze: true` executes, so it is allowed only for reads.
- **Reasons.** If the grant sets `require_reason`, every call needs a non-empty `reason`; it is stored with the audit row.

## Find and stop your own queries

`db_activity` lists what the gateway is running for *you* on a database (`pid`, `request_id`, `state`, `wait_event`, `running_ms`). `cancel_query` with one of those `request_id`s stops it; the stopped call answers `cancelled`. You can only see and cancel your own token's requests.

With `x-dbmcp-run-id` both cover only that run. Without it they cover every run that shares the token — but only if your account does not set `require_upstream` and `run_scoped` is `false` or absent; otherwise the call is refused. Pass `run_scoped: true` when the call must stay within your run:

```json
{"name": "cancel_query", "arguments": {
  "server": "prod", "database": "app",
  "request_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "run_scoped": true}}
```

- The gateway answers only if the call carries the run header; otherwise it refuses with `invalid_arguments` (`-32602`) and lists or cancels nothing. An SSO session is always refused.
- A gateway too old to know the argument refuses it the same way, so send it without checking versions. Treat the refusal as final: do not retry without `run_scoped`.
- The run id is a claim, so this is a filter, not isolation. Runs that must not reach each other's statements need separate service accounts.

## See also

- [Other MCP-aware agents](other-agents.md) — client config shapes
- [MCP tool surface](../initial-idea/03-mcp-tools.md) — every tool, argument and error code
- [Service tokens](../initial-idea/14-service-tokens.md) — design and operator runbook
