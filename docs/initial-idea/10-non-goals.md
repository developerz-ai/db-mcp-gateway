# 10 — Non-Goals

What we are deliberately not building. Listed here so they don't creep in.

## Not a BI tool

No dashboards. No saved queries. No charts. No "share this result with my team." Agents are the read-out; if humans want a dashboard, they have Metabase / Superset / Looker / whatever they already use. Adding even one chart starts a feature treadmill that ends in us competing with Tableau and losing.

## Not a query builder

No visual SQL editor. No "drag a table onto a canvas." The agent writes the SQL; the human writes prompts. If a person wants to write SQL by hand against the gateway, that's a sign they should be using psql with their own credential, not this product.

## Not a credential vault

We *use* a secret manager; we don't *replace* one. The gateway is not Vault, not 1Password, not AWS Secrets Manager. If you have one of those, point us at it. If you don't, get one first.

## Not a SaaS

There is no hosted version, no control plane, no "sign up." Every install is self-hosted, single-tenant, in the customer's own infra. We will never see your queries.

## Not multi-tenant

One install = one organization. Two organizations sharing one gateway is explicitly unsupported. If you have two organizations, run two gateways.

## Not a write-heavy tool

Writes are possible (see [06-permissions](06-permissions.md)) but the system is shaped around read-only debugging. Migrations, data corrections, bulk updates — those belong in your existing CI/CD or runbooks, not in an agent's tool call.

## Not a database

The state Postgres is internal plumbing for sessions + audit. It's not exposed, not extensible, not queryable through the gateway's own MCP tools. Don't try to use it as application storage.

## Not an AI product

There is no embedded LLM, no vector store, no "natural language to SQL" feature inside the gateway. The agent calling us has all of that. Our job is plumbing.

## Not a tool for end users

The user of this system is an *engineer running an AI agent*. Not a customer-success rep checking an order. Not a finance analyst pulling numbers. Not a marketing person querying campaigns. Those use cases are real but they need a different product with different guardrails.

## Not "agentic" anything

We don't run agents. We don't host agents. We don't coordinate agents. We expose tools to whatever agent the user is already running.

## Not a network proxy

We don't tunnel arbitrary DB protocol traffic. We expose specific MCP tools that internally run specific queries. "Just let me connect to the DB through you" is the thing this product *replaces*; it's not a feature we add later.

## Not an admin UI

Permissions live in YAML in git. There is no `/admin` web UI for editing groups, granting access, or rotating credentials. The platform/infra teams who deploy this prefer config-as-code and we are not going to talk them out of it.
