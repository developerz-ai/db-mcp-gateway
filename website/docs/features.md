# Features

Comprehensive feature breakdown of db-mcp-gateway with technical benefits and implementation details.

---

## 🔐 Credential Security

### Credentials Never Leave the Gateway
- **What it does:** Database credentials are stored exclusively in the gateway's configuration and never exposed to clients or logs
- **How it works:** Clients receive JWT tokens via SSO, gateway authenticates to databases using its own credentials
- **Security benefit:** No database URLs, passwords, or connection strings ever reach AI agents or developer laptops
- **Audit benefit:** Credential rotation only required at gateway, not across every developer's machine

### Token-Based Authentication
- **What it does:** Clients authenticate via SSO and receive short-lived JWT tokens (8h default)
- **How it works:** OIDC-compliant SSO flow (Google Workspace, Okta, Microsoft Entra, Authentik, Keycloak)
- **Security benefit:** No shared passwords, tokens expire automatically, no credential cleanup required
- **Operations benefit:** SSO integration leverages existing corporate directory and group memberships

---

## 👤 Identity and Attribution

### End-to-End User Identity
- **What it does:** Every database query is attributed to the specific SSO user who initiated it
- **How it works:** JWT token contains user identity and group memberships, propagated to audit log
- **Security benefit:** Complete attribution for compliance and security investigations
- **Operations benefit:** No more "who ran this query?" investigations

### Group-Based Authorization
- **What it does:** Database access granted via group memberships defined in YAML configuration
- **How it works:** Users inherit grants from all groups they belong to, evaluated per-query
- **Security benefit:** Access control follows organizational structure (teams, departments)
- **Operations benefit:** User onboarding/offboarding handled via SSO, not database permissions

---

## 🛡️ Query Safety and Resource Limits

### Read-Only Enforcement
- **What it does:** All queries default to read-only access unless explicitly granted write permissions
- **How it works:** Gateway uses read-only database roles and enforces read-only at query analysis layer
- **Security benefit:** AI agents cannot accidentally modify data, even if prompted incorrectly
- **Operations benefit:** Production data protection without monitoring every agent conversation

### Statement Timeouts
- **What it does:** Every query has configurable execution time limits (default 5000ms)
- **How it works:** Timeout enforced both at gateway level and via PostgreSQL `statement_timeout`
- **Performance benefit:** Prevents runaway queries from impacting database performance
- **Operations benefit:** No more "who locked up production?" incidents

### Row Limits
- **What it does:** Result sets automatically truncated after configurable row count (default 1000 rows)
- **How it works:** Gateway applies `LIMIT` clauses and/or truncates results after execution
- **Performance benefit:** Prevents large result sets from overwhelming network or agent context
- **Operations benefit:** Cost control on databases that charge per query byte

### Schema Filtering
- **What it does:** Grants can restrict access to specific schemas (allow/deny lists)
- **How it works:** Query analysis enforces schema restrictions before execution
- **Security benefit:** Multi-tenant databases can expose only relevant schemas per team
- **Operations benefit:** Single database server can serve multiple security domains

---

## 📋 Permissions and Configuration

### YAML-Based Configuration
- **What it does:** All permissions defined in human-readable YAML files reviewed via PR
- **How it works:** Config file maps groups → servers → databases → actions with constraints
- **Operations benefit:** No admin UI to maintain, permissions tracked in git history
- **Security benefit:** Changes require code review, not ad-hoc admin panel clicks

### Granular Grant System
- **What it does:** Four-tier permission structure: group × server × database × action
- **How it works:** Each grant can specify `query_read`, `query_write`, `describe_schema`, `explain`, etc.
- **Flexibility benefit:** Can grant schema-only access to analysts, full access to DBAs
- **Security benefit:** Principle of least privilege enforced at technical level

### Constraint System
- **What it does:** Each grant can specify constraints: `require_reason`, `row_limit`, `statement_timeout_ms`, `allowed_schemas`, `time_windows`
- **How it works:** Constraints evaluated per-query before execution
- **Compliance benefit:** Production queries automatically require incident ticket numbers
- **Operations benefit:** Different constraints for development vs. production environments

---

## 📊 Audit and Compliance

### Synchronous Audit Log
- **What it does:** Every database query logged before result returned to client
- **What it captures:** User identity, SQL statement, reason (if required), row count, duration, outcome
- **How it works:** Append-only log in gateway's state database, with a configurable retention TTL and an hourly pruner
- **Compliance benefit:** Complete query history for security reviews and compliance audits

### Query History API

- **Status:** Shipped via [#169](https://github.com/developerz-ai/db-mcp-gateway/issues/169). The `get_query_history` MCP tool reads from the same audit log; users see only their own queries.
- **What it does:** Lets a user retrieve their own recent queries (SQL, timestamp, duration, row count, outcome) for a configured `(server, database)`.
- **How it works:** Reads `audit_calls` rows scoped by `user_sub = $1 AND server_name = $2 AND database_name = $3` (the SSO-verified identity, never a client-supplied field). Requires the standalone `history_read` grant.
- **Privacy benefit:** Users see their own history, not teammates' queries
- **Operations benefit:** Self-service audit access reduces support burden

### Retention (hot tier shipped; archive/stream on the roadmap)

- **What it does today:** Audit logs live in the gateway's Postgres with a configurable TTL (default 90 days) and an hourly pruner that deletes past it.
- **Not shipped:** Cold-tier archive (S3/GCS/Azure) and streaming sinks (OTLP/syslog/stdout) for SIEM integration are [roadmap Phase 4](initial-idea/11-roadmap.md) — there is no `archive` or `stream` config key yet.
- **Operations benefit:** Hot data stays fast today; cold-tier retention lands when Phase 4 ships.

---

## 🤖 MCP Integration

### Complete MCP Tool Surface

- **What it does:** Seven MCP tools cover all database interaction patterns
- **Tools included:**
  - `list_servers` - Enumerate target servers visible to the caller
  - `list_databases` - Enumerate available databases on a server
  - `describe_schema` - Get table/column metadata with types
  - `sample_table` - Preview data with configurable sample size
  - `run_query` - Execute SQL with safety limits
  - `explain` - Get query execution plans
  - `get_query_history` - Retrieve a user's own recent queries from the audit log

### Multi-Database Support
- **What it does:** Single gateway instance fronts PostgreSQL and MongoDB targets (MySQL/MSSQL are rejected at boot — see [multi-db](usage/multi-db.md))
- **How it works:** Abstracted database drivers with unified MCP interface
- **Operations benefit:** One deployment serves mixed database environments
- **Workflow benefit:** AI agents can cross-reference data across database types

### Claude Code Optimization
- **What it does:** Dedicated integration patterns for Claude Code (Anthropic's AI coding agent)
- **Features:** Project-scoped configs, automatic SSO flow, query attribution in conversations
- **Developer benefit:** `claude mcp add` and start querying, no manual authentication

---

## 🏗️ Deployment and Operations

### Single-Command Deployment
- **What it does:** Gateway runs as single Docker container with one Postgres dependency
- **How it works:** `docker pull` + YAML config + Postgres state database
- **Operations benefit:** No complex multi-service deployments or Kubernetes clusters required
- **Testing benefit:** Easy to run locally for development and testing

### Health and Readiness Endpoints
- **What it does:** `/readyz` endpoint for load balancer health checks (state-DB reachable + not shutting down); `/healthz` is a plain liveness probe (200 if the binary is up)
- **How it works:** Returns 200 if gateway can accept queries, 503 if database connection fails
- **Operations benefit:** Standard load balancer integration for high availability

### Reproducible Builds
- **What it does:** Every `v*` git tag produces reproducible OCI images
- **How it works:** Multi-arch builds (amd64 + arm64) with content-addressable digests
- **Security benefit:** Images can be verified via digests, no mutable `latest` tags in production
- **Operations benefit:** Consistent behavior across development, testing, and production

---

## 🔌 Enterprise Integration

### SSO Integration
- **What it does:** SSO via any OIDC-compliant identity provider — the gateway speaks generic OIDC, not provider-specific integrations
- **Security benefit:** No user accounts to manage, leverage existing corporate directory
- **Operations benefit:** User onboarding/offboarding handled centrally, not per application

### SIEM Integration (roadmap, not shipped)

- **What it will do:** Stream audit logs to a SIEM via OTLP, syslog, or stdout sinks
- **Status:** No streaming sink is implemented and there is no config key for one; [roadmap Phase 4](initial-idea/11-roadmap.md). The application logs the gateway process itself emits (JSON-per-line to stdout) are operational logs, not an audit export, and don't satisfy this.

### Multi-Cloud Archive (roadmap, not shipped)

- **What it will do:** Archive audit logs to S3, Google Cloud Storage, or Azure Blob Storage past the hot-tier retention window
- **Status:** No archive exporter is implemented and there is no `archive` config key; [roadmap Phase 4](initial-idea/11-roadmap.md).

---

## 🎯 Platform Features

### Configurable Time Windows
- **What it does:** Grants can specify valid time ranges (e.g., business hours only)
- **How it works:** Queries outside time windows automatically rejected with clear error messages
- **Security benefit:** Restrict production access to on-call hours
- **Compliance benefit:** Enforce "no production access on weekends" policies automatically

### Reason Requirement
- **What it does:** Production grants can require human-readable reason per query
- **How it works:** Gateway rejects queries without reason, reason stored in audit log
- **Compliance benefit:** Every production query tied to incident ticket or user story
- **Operations benefit:** Audit reviews can quickly understand query context

### Constraint Evaluation
- **What it does:** All constraints evaluated before query execution, fast rejection
- **How it works:** Query analysis checks row limits, timeouts, schema access before hitting database
- **Performance benefit:** Invalid queries rejected without database round-trip
- **Operations benefit:** Clear error messages help users understand permission boundaries

---

## 🚫 Security by Design

### No Admin UI
- **What it does:** Permissions managed exclusively via YAML files, not web interfaces
- **Security benefit:** No SQL injection via admin panels, no ad-hoc permission changes
- **Operations benefit:** All permission changes tracked in git history with code review

### No Credential Exposure
- **What it does:** Database credentials never appear in logs, error messages, or API responses
- **Security benefit:** Logs can be safely shared without redaction
- **Operations benefit:** Debugging and support without credential exposure risks

### No Self-Elevation
- **What it does:** Agents cannot grant themselves additional permissions
- **How it works:** Permission evaluation happens server-side, agents cannot modify gateway config
- **Security benefit:** AI agents limited to defined grants, cannot escape constraints
- **Operations benefit:** Prompt injection cannot expand the agent's server-side permissions or bypass grant constraints
