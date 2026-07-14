# 01 — Overview

## One-line

A self-hosted MCP gateway that brokers credentialled, audited, read-only database access for AI agents.

## The problem

AI coding agents are excellent at debugging when they can see the data. The status quo for giving them that visibility is to paste a database URL into the agent's config. That URL is:

- a long-lived shared credential
- sitting on developer laptops in plaintext
- ungated by role
- unaudited — nobody knows what queries ran, by whom, against which dataset
- often *production* because that's where the interesting bugs live

This does not scale past a handful of trusted engineers, and security teams will (correctly) shut it down the moment they notice.

## The shape of the fix

| Today | With gateway |
|---|---|
| DB URL pasted into laptop agent config | Gateway URL pasted once; no DB credentials ever leave the gateway |
| One shared role per environment | Per-database read-only role, statement timeout + row cap at the DB level |
| No identity — queries are anonymous to the DB | SSO identity flows through to every query and every log line |
| No audit trail | Every query logged with who/what/why/when, configurable retention |
| Permissions live nowhere | Permissions live in YAML, in git, reviewed by PR |

## Who it's for

Platform / infra / security teams at companies where engineers are using AI agents (Claude Code, Cursor, etc.) and they need to give those agents safe database visibility.

## Distribution shape

- Single static Rust binary
- Published as a Docker image on Docker Hub
- Example `docker-compose.yml` repo for "fork, edit `config.yaml`, `docker compose up`"
- Helm chart and Kubernetes manifests later (see [11-roadmap](11-roadmap.md))

## Non-negotiables

1. **Credentials never leave the gateway.** The DB URL is in gateway-side config or a secret manager; it is never returned in any API response, log line, or error.
2. **Identity is end-to-end.** Every query carries an SSO-verified user identity from agent → gateway → audit log.
3. **Read-only by default.** Write access is a separate, explicit, audited feature (see [06-permissions](06-permissions.md)).
4. **Config as code.** No admin UI for permissions; YAML reviewed via PR is the source of truth.
5. **Plumbing, not a product.** No BI features, no query builder, no end-user UX. The agent is the UX.

See also: [00-seed](00-seed.md) for the original framing.
