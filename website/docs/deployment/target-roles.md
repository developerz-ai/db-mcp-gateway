# Target roles per engine

The gateway never creates, widens or owns a database role (MUST #3); you provision one per database with your own admin credentials, and the gateway connects as it. Table, collection and key scoping is the role's job — a grant has no table filter ([spec 06](../initial-idea/06-permissions.md)). Boot refuses the stock superuser names (`postgres` on Postgres, `default` on Redis), but it cannot see real privileges: a superuser under another name is your mistake to avoid.

Store each password in your secret manager and reference it as `${ENV:…}` or `${FILE:…}` in `databases[].password`.

`db-mcp-gateway roles --config config.yml` prints these statements filled in from your config (print only), and `db-mcp-gateway doctor --config config.yml` connects as each configured Postgres role and reports superuser attributes, write privileges on a read role and tables it cannot read — see the [operator CLI](cli.md). Neither grants anything.

## PostgreSQL

`app_owner` stands for the role that owns your tables (the one migrations run as).

```sql
-- read role: one per database
create role mcp_gateway_prod_app_ro with login password :'pw';
grant connect on database app to mcp_gateway_prod_app_ro;
grant usage on schema public to mcp_gateway_prod_app_ro;
grant select on all tables in schema public to mcp_gateway_prod_app_ro;
-- tables app_owner creates later. Without `for role app_owner`, default
-- privileges cover only objects created by whoever runs this statement, and
-- the next migration's tables are unreadable.
alter default privileges for role app_owner in schema public
  grant select on tables to mcp_gateway_prod_app_ro;

-- defence in depth; the gateway also sets a per-transaction timeout
alter role mcp_gateway_prod_app_ro set statement_timeout = '30s';
alter role mcp_gateway_prod_app_ro set idle_in_transaction_session_timeout = '60s';
```

Repeat the `usage` / `select` / `alter default privileges` lines for each schema the gateway may read. To narrow, grant `select` on named tables instead of `all tables`.

Optional write role, only for a database with a `query_write` grant (wired as `write_role` / `write_password`):

```sql
create role mcp_gateway_prod_app_rw with login password :'rw_pw';
grant connect on database app to mcp_gateway_prod_app_rw;
grant usage on schema public to mcp_gateway_prod_app_rw;
grant select, insert, update, delete on table orders, order_items to mcp_gateway_prod_app_rw;
grant usage on all sequences in schema public to mcp_gateway_prod_app_rw;
alter role mcp_gateway_prod_app_rw set statement_timeout = '30s';
```

No `create`, `truncate`, `references` or ownership: the gateway refuses DDL anyway, and the role should agree. The introspection tools need nothing extra — `table_stats` lists what the read role can `select`; `db_activity` / `cancel_query` act on the gateway's own roles' backends, which a role may always do for itself.

Check it, as the new role: `select 1 from <table> limit 1` works, `insert` into it fails (read role).

### Keep extension schemas that hold SQL text out of reach

Some extensions keep SQL text in tables: pg_cron's `cron.job` (every scheduled command) and `cron.job_run_details` (every run's command). The guard refuses anything qualified with `cron.` and the distinctive `job_run_details` anywhere, but not a bare `job` — that name is too common in application schemas to refuse. A read role with `cron` on its `search_path` could read `select command from job` unqualified. So the read role must have **no `USAGE` on schema `cron`**, nor on any other extension schema that stores SQL text, and must not have such a schema on its `search_path`:

```sql
revoke all on schema cron from mcp_gateway_prod_app_ro;
revoke all on all tables in schema cron from mcp_gateway_prod_app_ro;
-- usage granted to PUBLIC reaches every role; revoke it there too if set
revoke usage on schema cron from public;
-- a search_path without extension schemas
alter role mcp_gateway_prod_app_ro set search_path = public;
```

Check it, as the read role: `select 1 from cron.job` fails with `permission denied for schema cron`, and `show search_path` names no extension schema. Apply the same to the write role.

## YugabyteDB (YSQL)

Same SQL as Postgres, run through `ysqlsh`; the server is `kind: postgres`. Do not connect as `yugabyte`, YSQL's superuser (boot only knows the name `postgres`). For cancellation, `host` must name one tserver, not a load balancer — see [multi-db](../usage/multi-db.md#yugabytedb).

## MongoDB

A user with the built-in `read` role on the target database, created in that database so the default `auth_database` (= the database name) authenticates it:

```js
// mongosh, as an admin
use app
db.createUser({
  user: "mcp_gateway_app_ro",
  pwd: passwordPrompt(),
  roles: [ { role: "read", db: "app" } ]
})
```

```yaml
servers:
  - name: prod-mongo
    kind: mongo
    host: mongo.prod.internal
    port: 27017
    tls: verify_full
    databases:
      - name: app
        role: mcp_gateway_app_ro
        password: ${FILE:/run/secrets/prod-mongo-app-ro}
        # auth_database: admin    # only if you created the user in `admin`
```

To narrow below a whole database, define a custom role with `find` / `listCollections` / `listIndexes` on specific collections instead of `read`. Optional cancellation on disconnect needs `inprog` + `killop` on the `cluster` resource (or `clusterManager`) — see [config reference §Mongo](config-reference.md#mongo). Mongo targets stay read-only whatever the grant, and need MongoDB 4.4+.

Check it: `db.auth("mcp_gateway_app_ro", …)` in `app`, a `find` works, an `insertOne` fails with `Unauthorized`.

## Redis, Dragonfly, Valkey

An ACL user, never `default`. The full recipe and the meaning of each part is in [config reference §Redis](config-reference.md#redis); the short form:

```text
ACL SETUSER gateway_ro on #<sha256-of-password> resetkeys %R~app:* resetchannels -@all +@read -keys
```

Add `-scan -dbsize` when key names are sensitive, `+select` for a database index other than `0`. Persist it (`ACL SAVE` or your config file) so a restart does not drop the user.

## MySQL, MSSQL

Not query targets: boot rejects `kind: mysql` and `kind: mssql`. (A MySQL 8 database can be the gateway's *permissions store*; that uses `PERMISSIONS_DB_DSN` and a role that owns its own tables — [admin API §Storage backend](admin-api.md#storage-backend).)
