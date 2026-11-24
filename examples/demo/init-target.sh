#!/bin/sh
# Target-DB init (postgres image, first boot only): the read-only role the
# gateway connects as, then the demo data. The gateway never connects as the
# superuser the image creates.
set -eu

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ro_password="$DEMO_RO_PASSWORD" -f /demo/seed.sql -f - <<'SQL'
CREATE ROLE mcp_demo_ro LOGIN PASSWORD :'ro_password';
GRANT CONNECT ON DATABASE shop TO mcp_demo_ro;
GRANT USAGE ON SCHEMA public TO mcp_demo_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_demo_ro;
ALTER ROLE mcp_demo_ro SET default_transaction_read_only = on;
SQL
