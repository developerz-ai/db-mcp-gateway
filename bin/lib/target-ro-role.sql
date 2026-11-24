-- The SELECT-only login the dev gateway connects as (config/dev.yaml), run by
-- bin/seed as the target's owner. Idempotent: rerunning it refreshes the
-- password and re-grants SELECT on every table that exists now. psql reads
-- the password from the RO_PASSWORD environment variable, never from argv.
\set ON_ERROR_STOP on
SET client_min_messages = warning;
\getenv ro_password RO_PASSWORD
SELECT 'CREATE ROLE gateway_ro LOGIN'
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_ro') \gexec
ALTER ROLE gateway_ro WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  PASSWORD :'ro_password';
ALTER ROLE gateway_ro SET default_transaction_read_only = on;
SELECT format('GRANT CONNECT ON DATABASE %I TO gateway_ro', current_database()) \gexec
GRANT USAGE ON SCHEMA public TO gateway_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO gateway_ro;
