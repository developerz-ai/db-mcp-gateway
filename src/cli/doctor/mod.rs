//! `doctor`: connect to each configured Postgres database as its configured
//! role(s) and report what the role can do that it should not — superuser
//! attributes, write or CREATE privileges on the read role, in-scope tables it
//! cannot read — plus the target's `max_connections` against this config's
//! connection budget. Catalog reads only, in a rolled-back `READ ONLY`
//! transaction; it never grants or revokes anything (MUST #3) — the fix is
//! the operator's, e.g. from `db-mcp-gateway roles`.

mod probe;

use std::time::Duration;

use clap::Args;
use db_mcp_gateway::config::secret::{SecretSite, SiteSecretError};
use db_mcp_gateway::config::{ConfigFile, Database, Password, Server, ServerKind, Tls};
use secrecy::ExposeSecret;
use sqlx::ConnectOptions;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use super::check::{cancel_pool_size, server_budget};
use super::roles::selected;
use super::{CliError, ConfigArg, EXIT_ERROR, EXIT_FAILED, EXIT_OK};
use probe::Privileges;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole catalog probe, client side. Each statement is also bounded on
/// the server (`statement_timeout` in `probe::privileges`), so a stuck catalog read never
/// holds a backend after `doctor` gives up.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub config: ConfigArg,
    /// Only this server.
    #[arg(long)]
    pub server: Option<String>,
    /// Only this database (of every server, or of `--server`).
    #[arg(long)]
    pub database: Option<String>,
    /// Schema the read role must be able to read; repeat for several.
    #[arg(long = "schema", default_value = "public")]
    pub schemas: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum Tier {
    Read,
    Write,
}

#[derive(Debug, Default)]
struct Tally {
    findings: usize,
    errors: usize,
}

pub async fn run(args: DoctorArgs) -> Result<u8, CliError> {
    let config = ConfigFile::from_file(&args.config.config)?;
    let targets = selected(&config, args.server.as_deref(), args.database.as_deref());
    if targets.is_empty() {
        return Err(CliError::Invalid(
            "no configured database matches --server/--database".to_string(),
        ));
    }
    let cancel = cancel_pool_size().map_err(CliError::Invalid)?;
    let mut tally = Tally::default();
    for (server, db) in targets {
        if server.kind != ServerKind::Postgres {
            println!(
                "{}/{}: skipped — doctor checks postgres targets only",
                server.name, db.name
            );
            continue;
        }
        let tiers = std::iter::once((Tier::Read, db.role.as_str(), &db.password)).chain(
            db.write_credentials()
                .map(|(role, password)| (Tier::Write, role, password)),
        );
        for (tier, role, password) in tiers {
            println!(
                "{}/{} {} role `{role}`:",
                server.name,
                db.name,
                tier_name(tier)
            );
            match inspect(server, db, role, password, tier, &args.schemas).await {
                Ok(privileges) => {
                    tally.findings += report(&privileges, tier, server_budget(server, cancel));
                }
                Err(err) => {
                    println!("  error: {err}");
                    tally.errors += 1;
                }
            }
        }
    }
    println!(
        "result: {} finding(s), {} error(s)",
        tally.findings, tally.errors
    );
    Ok(match tally {
        Tally { errors: 1.., .. } => EXIT_ERROR,
        Tally { findings: 1.., .. } => EXIT_FAILED,
        _ => EXIT_OK,
    })
}

async fn inspect(
    server: &Server,
    db: &Database,
    role: &str,
    password: &Password,
    tier: Tier,
    schemas: &[String],
) -> Result<Privileges, String> {
    let secret = password.resolve_async().await.map_err(|error| {
        let site = match tier {
            Tier::Read => SecretSite::ReadPassword {
                server: server.name.clone(),
                database: db.name.clone(),
            },
            Tier::Write => SecretSite::WritePassword {
                server: server.name.clone(),
                database: db.name.clone(),
            },
        };
        SiteSecretError { site, error }.to_string()
    })?;
    let options = connect_options(server, db, role).password(secret.expose_secret());
    let mut conn = tokio::time::timeout(CONNECT_TIMEOUT, options.connect())
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|err| {
            format!(
                "could not connect ({})",
                db_mcp_gateway::state::connect_error_class(&err)
            )
        })?;
    within(PROBE_TIMEOUT, probe::privileges(&mut conn, schemas)).await
}

async fn within<T>(
    limit: Duration,
    probe: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, String> {
    tokio::time::timeout(limit, probe)
        .await
        .map_err(|_| "catalog query timed out".to_string())?
        .map_err(|err| format!("catalog query failed ({})", sqlx_class(&err)))
}

/// What `exec::pg` connects with (`connect_options`, crate-private there).
fn connect_options(server: &Server, db: &Database, role: &str) -> PgConnectOptions {
    let ssl_mode = match server.tls {
        Tls::Required => PgSslMode::Require,
        Tls::VerifyFull => PgSslMode::VerifyFull,
        Tls::Insecure => PgSslMode::Disable,
    };
    let options = PgConnectOptions::new()
        .host(&server.host)
        .port(server.port)
        .username(role)
        .database(&db.name)
        .ssl_mode(ssl_mode)
        .disable_statement_logging();
    match &server.tls_ca_file {
        Some(ca) => options.ssl_root_cert(ca),
        None => options,
    }
}

fn sqlx_class(err: &sqlx::Error) -> String {
    match err {
        sqlx::Error::Database(db) => db.code().map_or_else(
            || "database error".to_string(),
            |code| format!("SQLSTATE {code}"),
        ),
        _ => "driver error".to_string(),
    }
}

/// Prints the role's lines; returns its finding count.
fn report(p: &Privileges, tier: Tier, budget: u32) -> usize {
    let mut findings = Vec::new();
    if !p.role_attributes.is_empty() {
        findings.push(format!(
            "role has {} — the gateway must never hold a superuser or admin credential",
            p.role_attributes.join(", ")
        ));
    }
    if matches!(tier, Tier::Read) {
        findings.extend(read_role_findings(p));
        if !p.default_read_only {
            println!(
                "  note: default_transaction_read_only is off (defence in depth: \
                 ALTER ROLE … SET default_transaction_read_only = on)"
            );
        }
    }
    for finding in &findings {
        println!("  finding: {finding}");
    }
    if findings.is_empty() {
        println!("  ok: no findings");
    }
    println!(
        "  budget: one replica may open {budget} connection(s) to this server; \
         target max_connections = {}",
        p.max_connections
    );
    findings.len()
}

fn read_role_findings(p: &Privileges) -> Vec<String> {
    let mut findings = Vec::new();
    if !p.writable.is_empty() {
        findings.push(format!("read role can write: {}", p.writable.join(", ")));
    }
    if p.can_create_in_database {
        findings.push("read role may CREATE schemas in the database".to_string());
    }
    if !p.create_schemas.is_empty() {
        findings.push(format!(
            "read role may CREATE in schema(s): {}",
            p.create_schemas.join(", ")
        ));
    }
    if !p.schemas_without_usage.is_empty() {
        findings.push(format!(
            "no USAGE on in-scope schema(s): {}",
            p.schemas_without_usage.join(", ")
        ));
    }
    if !p.unreadable.is_empty() {
        findings.push(format!(
            "cannot SELECT in-scope relation(s): {}",
            p.unreadable.join(", ")
        ));
    }
    findings
}

fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Read => "read",
        Tier::Write => "write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_catalog_probe_that_never_answers_times_out() {
        let stuck = std::future::pending::<Result<(), sqlx::Error>>();
        assert_eq!(
            within(Duration::from_millis(10), stuck).await,
            Err("catalog query timed out".to_string())
        );
    }
}
