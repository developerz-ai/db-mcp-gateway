//! The operator CLI: everything the binary does besides serving (spec 08
//! §"Operator CLI", website/docs/deployment/cli.md).
//!
//! Output is the product here, so commands write to stdout/stderr directly
//! rather than through `tracing`: the boot path's JSON log subscriber is never
//! installed for a CLI run, and none of these commands print a credential.
//!
//! Exit codes: [`EXIT_OK`] success, [`EXIT_FAILED`] a negative answer (invalid
//! config, unhealthy, doctor findings, a refused admin call), `2` a usage
//! error (clap), [`EXIT_ERROR`] the command could not run (I/O, network,
//! database unreachable).

mod admin;
mod check;
mod doctor;
mod error;
mod healthcheck;
mod mint;
mod roles;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

pub use check::tls_warnings;
pub use error::CliError;

pub const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
pub const EXIT_ERROR: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "db-mcp-gateway",
    version,
    about,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Path to the YAML config file (servers + permissions). Required to
    /// serve; spec 08-config.md says no half-loaded state.
    #[arg(
        long,
        env = "DB_MCP_GATEWAY_CONFIG",
        required_unless_present = "healthcheck"
    )]
    pub config: Option<PathBuf>,
    /// Validate the config and exit without booting: every error, warnings,
    /// and the connection budget. Exit 0 valid, 1 invalid.
    #[arg(long, conflicts_with = "healthcheck")]
    pub check: bool,
    /// With `--check`: leave `${ENV:…}` / `${FILE:…}` references unresolved,
    /// so CI can validate a config without its secrets.
    #[arg(long, requires = "check")]
    pub no_secrets: bool,
    /// Probe this host's own `/healthz` (from `GATEWAY_BIND`) and exit 0 when
    /// it answers 200, 1 otherwise — a healthcheck for the distroless image.
    #[arg(long)]
    pub healthcheck: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Log in through the gateway's own OAuth flow (loopback redirect + PKCE)
    /// and store the session token for the admin commands.
    Login(admin::LoginArgs),
    /// Admin API: list or apply grants.
    #[command(subcommand)]
    Grants(admin::GrantsCommand),
    /// Admin API: revoke every session of one user.
    #[command(subcommand)]
    Sessions(admin::SessionsCommand),
    /// Admin API: read the tool-call audit log.
    #[command(subcommand)]
    Audit(admin::AuditCommand),
    /// Mint a static service-account bearer token (spec 14). Prints it once.
    MintServiceToken(mint::MintArgs),
    /// Print the SQL that provisions each configured database's read (and
    /// write) role. Prints only; never connects.
    Roles(roles::RolesArgs),
    /// Connect as each configured role and report privilege drift. Read-only
    /// queries; never grants anything.
    Doctor(doctor::DoctorArgs),
}

/// `--config`, for the subcommands that read the gateway YAML.
#[derive(Debug, Args)]
pub struct ConfigArg {
    /// Path to the gateway YAML config.
    #[arg(long, env = "DB_MCP_GATEWAY_CONFIG")]
    pub config: PathBuf,
}

/// What `main` does with a parsed command line.
#[derive(Debug)]
pub enum Action {
    /// Boot the gateway with this config.
    Serve(PathBuf),
    /// Run a CLI command and exit with its code.
    Tool(Tool),
}

#[derive(Debug)]
pub enum Tool {
    Check { config: PathBuf, no_secrets: bool },
    Healthcheck,
    Command(Command),
}

impl Cli {
    /// Clap guarantees `config` is present unless `--healthcheck` or a
    /// subcommand was given; [`Action::Serve`] without one is unreachable.
    pub fn into_action(self) -> Result<Action, CliError> {
        if let Some(command) = self.command {
            return Ok(Action::Tool(Tool::Command(command)));
        }
        if self.healthcheck {
            return Ok(Action::Tool(Tool::Healthcheck));
        }
        let config = self
            .config
            .ok_or_else(|| CliError::Usage("--config is required".to_string()))?;
        if self.check {
            return Ok(Action::Tool(Tool::Check {
                config,
                no_secrets: self.no_secrets,
            }));
        }
        Ok(Action::Serve(config))
    }
}

/// Run one CLI command to completion on its own small runtime.
pub fn run(tool: Tool) -> ExitCode {
    let code = match tool {
        Tool::Check { config, no_secrets } => Ok(check::run(&config, no_secrets)),
        Tool::Healthcheck => block_on(healthcheck::run()),
        Tool::Command(command) => run_command(command),
    };
    match code {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run_command(command: Command) -> Result<u8, CliError> {
    match command {
        Command::Login(args) => block_on(admin::login(args)),
        Command::Grants(command) => block_on(admin::grants(command)),
        Command::Sessions(command) => block_on(admin::sessions(command)),
        Command::Audit(command) => block_on(admin::audit(command)),
        Command::MintServiceToken(args) => mint::run(&args),
        Command::Roles(args) => roles::run(&args),
        Command::Doctor(args) => block_on(doctor::run(args)),
    }
}

fn block_on<F>(future: F) -> Result<u8, CliError>
where
    F: std::future::Future<Output = Result<u8, CliError>>,
{
    // rustls needs the process-wide provider before the first TLS handshake,
    // as on the boot path.
    db_mcp_gateway::transport::tls::install_crypto_provider();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| CliError::Io {
            what: "start the async runtime".to_string(),
            source,
        })?;
    runtime.block_on(future)
}

#[cfg(test)]
mod tests;
