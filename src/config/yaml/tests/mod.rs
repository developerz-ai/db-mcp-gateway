//! `ConfigFile` parse + validate tests, grouped by YAML section.

mod admin_store;
mod boot_rules;
mod load;
mod logging;
mod parse_errors;
mod reload_diff;
mod service_accounts;
mod structure;

const SAMPLE: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: Customer-facing prod
    host: prod.db.internal
    port: 5432
    tls: required
    databases:
      - name: app
        role: mcp_gateway_prod_app_ro
        password: vault:secret/prod/app_ro
        description: Main app DB
      - name: billing
        role: mcp_gateway_prod_billing_ro
        password: vault:secret/prod/billing_ro
  - name: staging
    kind: postgres
    host: staging.db.internal
    databases:
      - name: app
        role: mcp_gateway_staging_app_ro
        password: hunter2

permissions:
  - group: backend-engineers
    grants:
      - server: staging
        database: "*"
        action: query_read
      - server: prod
        database: "*"
        action: schema_read
"#;
