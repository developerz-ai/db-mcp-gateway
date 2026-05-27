# 00 — Seed

The original framing of the project, captured verbatim before it gets refined into spec docs. Everything in `01-*` onwards is a derived view; this file is the source of truth for *intent*.

## What it is

A self-hosted gateway your team deploys once on your own infrastructure. Developers don't run anything locally — they just add your gateway's URL as an MCP server in their AI agent. From that moment on, their agent can debug across all your databases without anyone ever handing out a real connection string.

## The shift it creates

Today: a dev needs to debug something, so they get a DB URL dropped in Slack, paste it into their agent's config, and now there's a production credential sitting in plaintext on a laptop. Multiply by team size. Nobody knows who ran what.

After: the gateway holds every credential. Devs authenticate to it with SSO. Their agent calls the gateway, the gateway runs the query under a tightly scoped read-only role, logs everything, returns results. Credentials never leave your infra.

## How it works end to end

You deploy the gateway as a Rust binary in a Docker container pulled from Docker Hub, plus a small Postgres for its own state. One YAML config file describes everything: which database servers exist, which databases on each server are exposed, who can access what, how long to keep logs.

Developers add the gateway to their agent's MCP config once — just a URL. First time they use it, the agent triggers an SSO login flow in their browser. After that, their token is cached and the agent has tools like *list databases*, *describe schema*, *sample table*, *run query*, *explain*. They ask their agent "why is this customer's invoice stuck," the agent introspects the schema, writes the query, runs it through the gateway, gets the answer.

## What it supports

Multiple database servers (prod cluster, staging cluster, analytics cluster, separate cloud accounts — whatever). Multiple databases on each server. Each database gets its own read-only Postgres role with statement timeouts and row limits enforced at the database level, not just in app code. The gateway picks the right credential per request based on which DB the user is targeting and what they're allowed to touch.

Permissions are defined in the YAML by group, with groups synced from SSO claims. Backend engineers might get full query access to staging and schema-only visibility into prod. On-call gets broader prod access but every query requires a reason string that gets logged. New hires get nothing until added to a group.

## Logging and retention

Every query is logged: who ran it, which database, the full SQL, the reason they provided, how many rows came back, how long it took, which agent client made the call. This is the audit trail security will ask for the first time an AI agent does something weird.

Retention is set in the config. Reasonable defaults: 90 days hot in the gateway's own Postgres for fast querying, then optional archival export to S3 or equivalent for longer compliance windows (1 year, 7 years, whatever your policy is). Old logs past the retention window get pruned automatically by a background job. You can also configure what gets logged — full SQL, redacted SQL with literals stripped, or metadata only — depending on how paranoid your compliance team is about query text containing PII.

## Why Rust, why this shape

Rust because this thing is a security boundary in front of production databases. Memory safety, predictable performance, single static binary, no runtime to patch. Small attack surface, easy to audit.

Docker Hub distribution because deployment should be `docker pull` and a config file — not a build pipeline. Teams clone an example repo, fill in their SSO details and database list, `docker compose up`, done.

Config-as-code because the people deploying this are platform/infra teams who want everything in git, reviewed via PR, with the same change-management as the rest of their infrastructure. A GUI would actively make this worse for them.

## What it isn't

Not a BI tool, not a query builder, not for end users. It's plumbing — a credential broker and audit layer designed specifically for the case where AI agents need database access and the old answer of "just give them the URL" doesn't scale safely.
