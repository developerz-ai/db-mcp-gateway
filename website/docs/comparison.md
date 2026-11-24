# Comparison

db-mcp-gateway next to the other ways an AI agent gets at a database: handing it a connection string, a hand-written MCP wrapper, an off-the-shelf MCP database server, and an infrastructure access gateway. Statements about other products describe their general shape as of writing; check their current docs before deciding on them.

---

## Positioning

db-mcp-gateway is an **MCP server that holds the database credentials** and puts SSO identity, per-group grants and a synchronous audit row in front of every tool call. It is not a connection pooler, not a SQL proxy, and not a general access platform.

| | db-mcp-gateway | Connection string in the agent | MCP database server / toolbox | Access gateway (session broker) |
|---|---|---|---|---|
| **Credential on the developer's machine** | None | Yes | Usually yes (DSN in the client's config), unless you host it centrally | No (brokered) |
| **Interface the agent sees** | MCP tools | Driver / CLI | MCP tools | Database wire protocol |
| **Identity on each query** | SSO user or `service:<name>` | The shared DB role | Usually the server's DB role | SSO user per session |
| **Per-query audit row before the result** | Yes, synchronous | No | Depends; usually logs at best | Session/query recording, varies by product |
| **Read-only by default** | Yes (role + read-only transaction + statement guard) | Only if the role is | Varies (some run reads in a read-only transaction) | Only if the role is |

---

## vs a connection string in the agent

```bash
# The credential now lives on a laptop, in shell history and in the agent's context
DATABASE_URL="postgres://user:password@prod-db:5432/app"
```

```bash
# No credential on the laptop; the first call triggers browser SSO
claude mcp add --transport http db-gateway https://db.internal.acme.com/mcp
```

| Aspect | Connection string | db-mcp-gateway |
|---|---|---|
| Credential exposure | High: laptops, logs, agent context | None: the gateway holds it |
| Attribution | The shared role | Each SSO user, per call |
| Audit trail | Whatever the database logs | One `audit_calls` row per call, committed before the response |
| Revoking one person | Rotate the shared password, redistribute it to everyone else | Remove them from the IdP group, or `revoke-sessions`; replicas converge within `SESSION_CACHE_TTL_SECONDS` (30 s), grant changes within `PERMISSIONS_CACHE_TTL_SECONDS` (60 s) at worst |
| Setup | Minutes | Hours: deploy, IdP app, roles, permissions |
| Latency | Direct | One extra hop plus two synchronous audit writes — [measured](benchmarks.md) |

Pick the connection string for personal or throwaway databases where nobody needs to know who ran what. Pick the gateway when the database matters and the agent should never hold its credential.

---

## vs a hand-written MCP wrapper

A wrapper is quick to write:

```python
@app.post("/query")
async def run_query(sql: str):
    return await database.execute(sql)
```

What it costs depends on how much of the following you end up rebuilding — we have not measured it and will not publish a number:

| Capability | Custom wrapper | db-mcp-gateway |
|---|---|---|
| OIDC login + session handling + MCP OAuth | You build and maintain it | Ships |
| Per-query identity in an audit row | You build and maintain it | Ships |
| Read-only enforcement that survives a clever query | You build and maintain it | Ships |
| Statement timeouts, row caps, cancellation on disconnect | You build and maintain it | Ships |
| A second database engine | Rebuild per engine | Add a `servers:` entry (Postgres, YugabyteDB, MongoDB, Redis-protocol) |
| Keeping all of the above correct as agents change | Yours | Upstream's |

If none of those rows matter to you, a wrapper may be cheaper — evaluate it.

---

## vs MCP database servers and toolboxes

There are many MCP servers that expose a database to an agent: per-engine servers (the original reference Postgres server, community MySQL / Mongo / Redis servers), multi-database servers such as DBHub, and configurable toolboxes such as Google's MCP Toolbox for Databases, where an operator declares parameterised SQL tools in a file.

They solve "give the agent tools for this database". The usual shape is a process the developer runs locally (stdio) with a DSN in its config, or a shared server running as one database role. What they typically leave to you:

| Concern | Typical MCP DB server / toolbox | db-mcp-gateway |
|---|---|---|
| Where the credential lives | Client config or the server's env | Only the gateway, never in a response, log or error |
| Who the caller is | The process; sometimes an auth layer you add | SSO user via OIDC, or a named service token |
| Per-group, per-database permissions | Usually none, or tool-level | `group × server × database × action` grants with constraints |
| Audit | Optional logging | Synchronous audit row per call; failed audit write fails the call |
| Free-form SQL vs fixed tools | Varies — toolboxes favour predeclared queries | Free-form `run_query` behind grants, plus fixed introspection tools |

A toolbox of predeclared queries is a narrower blast radius than free-form SQL. If the questions your agents ask are known in advance, that is a real advantage; you can also run such a toolbox behind your own auth. The gateway is for when engineers need ad-hoc debugging queries and you need to know who ran each one.

---

## vs infrastructure access gateways

Teleport (database access), StrongDM, HashiCorp Boundary and similar products broker human (and machine) access to databases: SSO login, short-lived or injected credentials, session recording and, in some products, query-level logs. They speak the database wire protocol, so `psql` and drivers work through them.

| Concern | Access gateway | db-mcp-gateway |
|---|---|---|
| Interface | DB wire protocol (any client) | MCP tools only |
| Scope | Servers, Kubernetes, databases, more | Databases for AI agents, nothing else |
| Agent-specific limits (row caps, result-size caps, `reason_required`, statement guard) | Generally not | Built in |
| Audit granularity | Session and, depending on product, query | One row per tool call, with reason, row count and outcome |
| Operations | A platform to run (or buy) | One container + one Postgres |
| Cost | Commercial tiers for most enterprise features | Open source (MIT) |

If you already run one of these for humans, it is a good way to give the *gateway* its network path to the databases. They complement each other: the access gateway governs connections, db-mcp-gateway governs what an agent may run and records it. Some access gateways have started adding MCP-facing features; compare those directly against the table above.

---

## Not the same layer: poolers and data governance

- **Connection poolers** (PgBouncer, pgcat, ProxySQL, RDS Proxy) reduce connection count. They do not authenticate people or audit queries. The gateway can sit *in front of* one — see the [pooler contract](deployment/pooler-contract.md) for what it needs from it.
- **Data governance platforms** (catalogs, masking, column-level policy across a warehouse) are broader. The gateway does no masking and no column-level policy; table and column scoping is the target-DB role's job ([spec 06](initial-idea/06-permissions.md)).

---

## Decision matrix

| Scenario | Fit |
|---|---|
| Engineers' agents need ad-hoc read access to production, attributed per person | db-mcp-gateway |
| Unattended agents (CI, runners) need audited, scoped DB access | db-mcp-gateway with [service tokens](usage/headless-agents.md) |
| Agents only ever need a fixed set of known queries | An MCP toolbox of predeclared queries (optionally behind your own auth) |
| Humans need `psql` through SSO with session recording | An access gateway |
| Too many connections to Postgres | A pooler |
| Personal or disposable database | Connection string |
| Masking or column-level policy | A governance product or database-native features |

---

## Migrating to the gateway

1. **Run it next to existing access.** Point one team's agents at it; nothing else changes.
2. **Recreate permissions as grants.** Map each existing role or wrapper rule to `group × server × database × action`; keep table scoping in the database roles.
3. **Switch agent configs** to `https://<gateway>/mcp` and remove DSNs from client configs and secrets on laptops.
4. **Rotate the old credentials** once nothing uses them, so the copies that leaked onto laptops stop working.

Effort depends on how many roles, agents and databases you have; we have no representative sample and will not invent an estimate.
