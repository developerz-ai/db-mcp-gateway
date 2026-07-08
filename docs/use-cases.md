# Use Cases

Real-world scenarios where db-mcp-gateway solves specific problems for AI agent infrastructure teams.

---

## Use Case 1: AI Agent Database Access for Development Teams

**Problem:** A development team wants to integrate Claude Code agents with their production databases for debugging and analysis, but giving agents direct database credentials is unacceptable from a security perspective.

**Solution:** Deploy db-mcp-gateway as a secure intermediary. Agents connect via MCP with SSO authentication, and all database access is logged and attributed to individual users.

### Implementation
```yaml
# Permissions config example
groups:
  - name: backend-team
    grants:
      - server: production
        databases: [app_db, analytics_db]
        actions: [query_read]
        constraints:
          row_limit: 1000
          statement_timeout_ms: 5000
          require_reason: true
```

### Benefits
- **Security:** No database credentials ever leave the gateway
- **Audit trail:** Every query is logged with user identity and reason
- **Granular control:** Row limits and timeouts prevent runaway queries
- **SSO integration:** Team members use existing Google/Okta/Microsoft accounts

### Workflow
1. Developer adds gateway to Claude Code via `claude mcp add`
2. First query triggers SSO login (browser-based)
3. Agent queries are automatically attributed to developer's identity
4. Audit log captures every SQL statement for compliance review

---

## Use Case 2: Analytics Without Direct Database Access

**Problem:** Business analysts and data scientists need database access for reporting and analysis, but managing individual database accounts and teaching SQL to everyone is operationally expensive.

**Solution:** Provide natural language interface to databases through AI agents, with db-mcp-gateway enforcing read-only access and resource limits.

### Implementation
```yaml
groups:
  - name: analytics-users
    grants:
      - server: data-warehouse
        databases: [sales_metrics, user_analytics]
        actions: [query_read, describe_schema]
        constraints:
          row_limit: 10000
          allowed_schemas: [public, analytics_]
```

### Benefits
- **Self-service:** Analysts ask questions in natural language
- **Safety:** Read-only enforcement prevents accidental data modification
- **Performance:** Resource limits prevent expensive analytical queries from impacting production
- **Compliance:** Every question-answer pair is logged for audit purposes

### Example Interactions
```
Analyst: "What was user growth over the last 6 months?"
Agent: [queries through gateway, returns chart-ready data]

Analyst: "Show me the top 10 countries by user count"
Agent: [generates SQL, applies limits, returns results]
```

---

## Use Case 3: Multi-Database AI Workflows

**Problem:** Complex AI workflows need to query across multiple databases (PostgreSQL, MySQL, MongoDB) with consistent security and auditing across all systems.

**Solution:** db-mcp-gateway acts as unified access layer, supporting multiple database types with consistent permission model and audit trail.

### Implementation
```yaml
groups:
  - name: workflow-automation
    grants:
      - server: postgres-primary
        databases: [app_db, user_profiles]
        actions: [query_read]
      - server: mysql-analytics
        databases: [event_logs, metrics]
        actions: [query_read]
      - server: mongo-documents
        databases: [content_store]
        actions: [query_read]
```

### Benefits
- **Unified security:** Single SSO login across all database types
- **Consistent auditing:** All queries logged regardless of database backend
- **Agent-friendly:** MCP interface works seamlessly across different databases
- **Operations:** One gateway instance manages all database access

### Workflow Example
```
Agent Workflow:
1. Query user profiles from PostgreSQL
2. Cross-reference with MySQL event logs  
3. Fetch related documents from MongoDB
4. Generate unified report

All queries go through same gateway with:
- Consistent authentication (SSO)
- Unified audit trail
- Per-query resource limits
```

---

## Use Case 4: Production Debugging with Compliance

**Problem:** On-call engineers need production database access for debugging incidents, but compliance requirements mandate individual attribution, reason logging, and strict time limits.

**Solution:** db-mcp-gateway enforces compliance requirements automatically while providing natural language interface for incident response.

### Implementation
```yaml
groups:
  - name: oncall-engineers
    grants:
      - server: production
        databases: [app_db]
        actions: [query_read, explain]
        constraints:
          require_reason: true
          statement_timeout_ms: 10000
          row_limit: 500
          time_windows:
            - start: "2024-01-01T00:00:00Z"
              end: "2024-12-31T23:59:59Z"
              allowed_hours: [0-23]  # All hours for oncall access
```

### Benefits
- **Compliance:** Every query requires reason (incident ticket, user story)
- **Safety:** Time limits and row caps prevent production impact
- **Attribution:** All queries linked to individual SSO accounts
- **Audit:** Complete incident timeline captured automatically

### Incident Response Flow
```
1. Alert triggers at 2 AM
2. On-call engineer asks: "Show me recent errors for user ID 12345"
3. Gateway requires: "Reason for production access?"
4. Engineer enters: "Investigating incident INC-2024-0142"
5. Query executes with enforced limits
6. Audit log captures: user, SQL, reason, timestamp, results
```

---

## Use Case 5: Gradual Migration from Direct Database Access

**Problem:** Organizations with existing direct database access want to migrate to safer AI agent workflows without disrupting current operations.

**Solution:** Deploy db-mcp-gateway alongside existing access patterns, gradually migrating teams to AI agent interface while maintaining full compatibility.

### Migration Strategy
```yaml
# Phase 1: Pilot with read-only analytics
groups:
  - name: analytics-pilot
    grants:
      - server: production
        databases: [analytics_db]
        actions: [query_read]

# Phase 2: Expand to development teams
groups:
  - name: dev-team-early-adopters
    grants:
      - server: staging
        databases: [app_db]
        actions: [query_read, describe_schema]

# Phase 3: Production debugging (compliance-approved)
groups:
  - name: oncall-production
    grants:
      - server: production
        databases: [app_db]
        actions: [query_read]
        constraints:
          require_reason: true
```

### Benefits
- **Low-risk migration:** Direct access continues during transition
- **Gradual adoption:** Teams migrate when ready, not all-at-once
- **Improved security:** Each migration step reduces credential exposure
- **Workflow continuity:** Existing operations continue uninterrupted

---

## Target Audiences

### Platform/SRE Teams
- **Why:** You own production databases and need to enable AI agent access safely
- **Value:** Self-service access for developers without credential management
- **Benefit:** Complete audit trail for compliance and security reviews

### Backend Development Teams  
- **Why:** You need production data for debugging and analysis
- **Value:** Natural language interface instead of writing complex SQL
- **Benefit:** Faster incident response with compliance built-in

### Data Analytics Teams
- **Why:** You need data access but don't want to manage database accounts
- **Value:** Self-service analytics without learning every database's SQL dialect
- **Benefit:** Consistent interface across PostgreSQL, MySQL, and MongoDB

### Security/Compliance Teams
- **Why:** You need to control and monitor all database access
- **Value:** Centralized audit log with SSO attribution and resource limits
- **Benefit:** Compliance requirements enforced automatically, not culturally

### AI/ML Platform Teams
- **Why:** You're building AI agent infrastructure that needs real data access
- **Value:** Production-ready MCP interface with enterprise security features
- **Benefit:** Deploy agents faster without building custom database integrations