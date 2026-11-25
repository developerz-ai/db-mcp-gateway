//! `roles`: print the statements that provision each configured database's
//! read role (and write role, when `write_role` is set) — the recipes of
//! website/docs/deployment/target-roles.md filled in from the config. Print
//! only: the gateway never creates or widens a role (MUST #3), so an operator
//! reviews and runs this with their own admin credentials.

use std::fmt::Write as _;

use clap::Args;
use db_mcp_gateway::config::{ConfigFile, Database, Server, ServerKind};
use db_mcp_gateway::exec::DEFAULT_STATEMENT_TIMEOUT_MS;

use super::{CliError, ConfigArg, EXIT_OK};

#[derive(Debug, Args)]
pub struct RolesArgs {
    #[command(flatten)]
    pub config: ConfigArg,
    /// Only this server.
    #[arg(long)]
    pub server: Option<String>,
    /// Only this database (of every server, or of `--server`).
    #[arg(long)]
    pub database: Option<String>,
    /// The role that owns the tables (the one migrations run as): default
    /// privileges are set for the tables it creates later.
    #[arg(long, default_value = "app_owner")]
    pub owner: String,
    /// Schema the roles may read; repeat for several.
    #[arg(long = "schema", default_value = "public")]
    pub schemas: Vec<String>,
}

pub fn run(args: &RolesArgs) -> Result<u8, CliError> {
    let config = ConfigFile::from_file(&args.config.config)?;
    let targets = selected(&config, args.server.as_deref(), args.database.as_deref());
    if targets.is_empty() {
        return Err(CliError::Invalid(
            "no configured database matches --server/--database".to_string(),
        ));
    }
    let blocks = targets
        .into_iter()
        .map(|(server, db)| render(server, db, args))
        .collect::<Result<Vec<_>, _>>()?;
    print!("{}", blocks.join("\n"));
    Ok(EXIT_OK)
}

/// Shared with `doctor`: the configured databases a `--server`/`--database`
/// filter selects, in file order.
pub fn selected<'a>(
    config: &'a ConfigFile,
    server: Option<&str>,
    database: Option<&str>,
) -> Vec<(&'a Server, &'a Database)> {
    config
        .servers
        .iter()
        .filter(|s| server.is_none_or(|name| s.name == name))
        .flat_map(|s| s.databases.iter().map(move |d| (s, d)))
        .filter(|(_, d)| database.is_none_or(|name| d.name == name))
        .collect()
}

fn render(server: &Server, db: &Database, args: &RolesArgs) -> Result<String, CliError> {
    match server.kind {
        ServerKind::Postgres => postgres(server, db, args),
        ServerKind::Mongo => Ok(mongo(server, db)),
        ServerKind::Redis => redis(server, db),
        ServerKind::Mysql | ServerKind::Mssql => Ok(format!(
            "-- {}: {:?} is not a query target\n",
            label(server, db),
            server.kind
        )),
    }
}

/// `server `a`, database `b``, plus the database's name on the server when it
/// has another one there. Safe inside a one-line comment: a name with a
/// line break cannot end the comment and start a statement.
fn label(server: &Server, db: &Database) -> String {
    let label = format!(
        "server `{}`, database `{}`",
        server.name.escape_debug(),
        db.name.escape_debug()
    );
    if db.connect_name() == db.name {
        return label;
    }
    format!(
        "{label} (`{}` on the server)",
        db.connect_name().escape_debug()
    )
}

/// A name that lands unquoted on a command line (a psql meta-command, a
/// redis-cli argument) must not carry a line break or other control
/// character, or it would end that line.
fn plain_line_arg<'a>(what: &str, value: &'a str) -> Result<&'a str, CliError> {
    if value.chars().any(char::is_control) {
        return Err(CliError::Invalid(format!(
            "{what} `{}` has a control character; provision it by hand",
            value.escape_debug()
        )));
    }
    Ok(value)
}

/// `CREATE ROLE` and `GRANT CONNECT` are cluster-wide; every other grant
/// lands in the database psql is connected to, so the recipe `\connect`s to
/// the configured one first.
fn postgres(server: &Server, db: &Database, args: &RolesArgs) -> Result<String, CliError> {
    let connect = psql_connect(plain_line_arg("database", db.connect_name())?);
    let database = quote_ident(db.connect_name());
    let read = quote_ident(&db.role);
    let owner = quote_ident(&args.owner);
    let mut sql = format!(
        "-- {}: read role\n\
         -- set the password out of band (psql: \\password {read}) and store it where\n\
         -- the config's `password:` reference points\n\
         CREATE ROLE {read} LOGIN;\n\
         GRANT CONNECT ON DATABASE {database} TO {read};\n\
         {connect}",
        label(server, db)
    );
    for schema in args.schemas.iter().map(|s| quote_ident(s)) {
        let _ = write!(
            sql,
            "GRANT USAGE ON SCHEMA {schema} TO {read};\n\
             GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {read};\n\
             ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {schema} GRANT SELECT ON TABLES TO {read};\n"
        );
    }
    let _ = write!(
        sql,
        "ALTER ROLE {read} SET default_transaction_read_only = on;\n\
         ALTER ROLE {read} SET statement_timeout = '{DEFAULT_STATEMENT_TIMEOUT_MS}ms';\n\
         ALTER ROLE {read} SET idle_in_transaction_session_timeout = '60s';\n"
    );
    if let Some((write_role, _)) = db.write_credentials() {
        let write = quote_ident(write_role);
        let _ = write!(
            sql,
            "-- write role (`write_role`): narrow the table list to what writes need\n\
             CREATE ROLE {write} LOGIN;\n\
             GRANT CONNECT ON DATABASE {database} TO {write};\n\
             {connect}"
        );
        for schema in args.schemas.iter().map(|s| quote_ident(s)) {
            let _ = write!(
                sql,
                "GRANT USAGE ON SCHEMA {schema} TO {write};\n\
                 GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {write};\n\
                 GRANT USAGE ON ALL SEQUENCES IN SCHEMA {schema} TO {write};\n"
            );
        }
        let _ = writeln!(
            sql,
            "ALTER ROLE {write} SET statement_timeout = '{DEFAULT_STATEMENT_TIMEOUT_MS}ms';"
        );
    }
    Ok(sql)
}

fn mongo(server: &Server, db: &Database) -> String {
    let auth_db = db
        .auth_database
        .as_deref()
        .unwrap_or_else(|| db.connect_name());
    format!(
        "// {}: read user — mongosh, as an admin\n\
         db = db.getSiblingDB({})\n\
         db.createUser({{ user: {}, pwd: passwordPrompt(), roles: [ {{ role: \"read\", db: {} }} ] }})\n",
        label(server, db),
        json_string(auth_db),
        json_string(&db.role),
        json_string(db.connect_name()),
    )
}

/// The gateway's read commands (`exec::redis` rejector) by name, minus
/// `SCAN` and `DBSIZE`: key patterns do not filter either, so they would
/// reveal key names and counts outside `%R~…`. `KEYS` is never granted.
const REDIS_READ_COMMANDS: &[&str] = &[
    "get",
    "mget",
    "strlen",
    "getrange",
    "substr",
    "getbit",
    "bitcount",
    "bitpos",
    "exists",
    "type",
    "ttl",
    "pttl",
    "expiretime",
    "pexpiretime",
    "hget",
    "hmget",
    "hgetall",
    "hkeys",
    "hvals",
    "hlen",
    "hexists",
    "hstrlen",
    "hrandfield",
    "hscan",
    "lrange",
    "llen",
    "lindex",
    "lpos",
    "smembers",
    "sismember",
    "smismember",
    "scard",
    "srandmember",
    "sscan",
    "sinter",
    "sunion",
    "sdiff",
    "sintercard",
    "zrange",
    "zrangebyscore",
    "zrangebylex",
    "zrevrange",
    "zrevrangebyscore",
    "zrevrangebylex",
    "zscore",
    "zmscore",
    "zcard",
    "zcount",
    "zlexcount",
    "zrank",
    "zrevrank",
    "zrandmember",
    "zscan",
    "xrange",
    "xrevrange",
    "xlen",
];

fn redis(server: &Server, db: &Database) -> Result<String, CliError> {
    let user = plain_line_arg("role", &db.role)?;
    if user.contains(char::is_whitespace) {
        return Err(CliError::Invalid(format!(
            "redis role `{user}` has whitespace; provision it by hand"
        )));
    }
    let select = if db.name == "0" { "" } else { " +select" };
    let commands: String = REDIS_READ_COMMANDS
        .iter()
        .map(|command| format!(" +{command}"))
        .collect();
    Ok(format!(
        "# {}: ACL user — narrow `%R~*` to the key patterns agents may read;\n\
         # SCAN/DBSIZE/KEYS stay off: they would list keys outside those patterns.\n\
         # `reset` first: on an existing user it clears every earlier rule, ACL\n\
         # selectors included, which would otherwise still allow their commands\n\
         # (Dragonfly has neither selectors nor `reset`: drop it there).\n\
         ACL SETUSER {user} reset on #<sha256-of-password> resetkeys %R~* resetchannels -@all{commands}{select}\n",
        label(server, db)
    ))
}

/// psql's `\connect` to `name` as a literal database name. A bare
/// `\connect "a=b"` hands psql a connection string (any `=`, or a
/// `postgresql://` prefix), so the name travels as an explicit `dbname`
/// value — escaped for libpq's quoting, then for psql's single-quoted
/// argument — and `-reuse-previous=on` keeps the host, port and user.
fn psql_connect(name: &str) -> String {
    let conninfo = format!(
        "dbname='{}'",
        name.replace('\\', "\\\\").replace('\'', "\\'")
    );
    format!(
        "\\connect -reuse-previous=on '{}'\n",
        conninfo.replace('\\', "\\\\").replace('\'', "''")
    )
}

/// Postgres identifier quoting: always quoted, so a mixed-case role keeps
/// its case and a database name with `-` stays one identifier.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn json_string(value: &str) -> String {
    serde_json::Value::String(value.to_string()).to_string()
}

#[cfg(test)]
mod tests;
