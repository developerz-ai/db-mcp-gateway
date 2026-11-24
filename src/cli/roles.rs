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
    let blocks: Vec<String> = targets
        .into_iter()
        .map(|(server, db)| render(server, db, args))
        .collect();
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

fn render(server: &Server, db: &Database, args: &RolesArgs) -> String {
    match server.kind {
        ServerKind::Postgres => postgres(server, db, args),
        ServerKind::Mongo => mongo(server, db),
        ServerKind::Redis => redis(server, db),
        ServerKind::Mysql | ServerKind::Mssql => format!(
            "-- server `{}`, database `{}`: {:?} is not a query target\n",
            server.name, db.name, server.kind
        ),
    }
}

fn postgres(server: &Server, db: &Database, args: &RolesArgs) -> String {
    let database = quote_ident(&db.name);
    let read = quote_ident(&db.role);
    let owner = quote_ident(&args.owner);
    let mut sql = format!(
        "-- server `{}`, database `{}`: read role\n\
         -- set the password out of band (psql: \\password {read}) and store it where\n\
         -- the config's `password:` reference points\n\
         CREATE ROLE {read} LOGIN;\n\
         GRANT CONNECT ON DATABASE {database} TO {read};\n",
        server.name, db.name
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
             GRANT CONNECT ON DATABASE {database} TO {write};\n"
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
    sql
}

fn mongo(server: &Server, db: &Database) -> String {
    let auth_db = db.auth_database.as_deref().unwrap_or(&db.name);
    format!(
        "// server `{}`, database `{}`: read user — mongosh, as an admin\n\
         use {auth_db}\n\
         db.createUser({{ user: {}, pwd: passwordPrompt(), roles: [ {{ role: \"read\", db: {} }} ] }})\n",
        server.name,
        db.name,
        json_string(&db.role),
        json_string(&db.name),
    )
}

fn redis(server: &Server, db: &Database) -> String {
    let select = if db.name == "0" { "" } else { " +select" };
    format!(
        "# server `{}`, database `{}`: ACL user — narrow `%R~*` to the key patterns agents may read\n\
         ACL SETUSER {} on #<sha256-of-password> resetkeys %R~* resetchannels -@all +@read -keys{select}\n",
        server.name, db.name, db.role
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
mod tests {
    use super::quote_ident;

    #[test]
    fn identifiers_are_quoted_and_escaped() {
        assert_eq!(quote_ident("AppRo"), "\"AppRo\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }
}
