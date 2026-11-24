//! Admin subcommands: thin clients of the audited admin API (spec 12). They
//! hold no privilege of their own — the caller's session must carry the
//! admin group, and every write lands in `permissions_audit` server-side.

mod client;
mod commands;
mod login;
mod session_file;

use std::path::PathBuf;

use clap::{Args, Subcommand};
use uuid::Uuid;

use super::{CliError, EXIT_OK};
use client::AdminClient;

pub use commands::{audit, grants, sessions};

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Gateway base URL, e.g. `https://gateway.example.com`.
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub token_file: Option<PathBuf>,
}

/// Which gateway, as whom.
#[derive(Debug, Args)]
pub struct Target {
    /// Gateway base URL. Default: the one `login` stored.
    #[arg(long)]
    pub url: Option<String>,
    /// Session file. Default: `$XDG_CONFIG_HOME/db-mcp-gateway/session.json`
    /// (else `~/.config/…`).
    #[arg(long)]
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum GrantsCommand {
    /// `GET /admin/v1/grants`, printed as JSON.
    List {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        user_id: Option<Uuid>,
        #[arg(long)]
        database_id: Option<Uuid>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        offset: Option<u32>,
    },
    /// `POST /admin/v1/grants` once per object of a JSON array file (each the
    /// create-grant body of spec 12). Stops at the first refusal; the grants
    /// created before it stay.
    Apply {
        #[command(flatten)]
        target: Target,
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum SessionsCommand {
    /// `POST /admin/v1/users/:id/revoke-sessions` — every session and refresh
    /// chain of one user.
    Revoke {
        #[command(flatten)]
        target: Target,
        /// The user's id, `user_sub` or email.
        user: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// `GET /admin/v1/audit/calls`, NDJSON to stdout.
    Query {
        #[command(flatten)]
        target: Target,
        /// A query parameter, `key=value`; repeat for several (see the admin
        /// API reference for the filters).
        #[arg(long = "param", value_parser = parse_param)]
        params: Vec<(String, String)>,
    },
    /// The same rows, streamed into a 0600 file.
    Export {
        #[command(flatten)]
        target: Target,
        #[arg(long = "param", value_parser = parse_param)]
        params: Vec<(String, String)>,
        #[arg(long)]
        out: PathBuf,
    },
}

fn parse_param(raw: &str) -> Result<(String, String), String> {
    raw.split_once('=')
        .filter(|(key, _)| !key.is_empty())
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .ok_or_else(|| format!("`{raw}` is not key=value"))
}

pub async fn login(args: LoginArgs) -> Result<u8, CliError> {
    let path = match args.token_file {
        Some(path) => path,
        None => session_file::default_path()?,
    };
    let session = login::run(&args.url).await?;
    session_file::save(&path, &session)?;
    println!(
        "logged in to {}; session stored in {}",
        session.url,
        path.display()
    );
    Ok(EXIT_OK)
}

impl Target {
    /// The client for this target, from the stored session.
    fn client(&self) -> Result<AdminClient, CliError> {
        let path = match &self.token_file {
            Some(path) => path.clone(),
            None => session_file::default_path()?,
        };
        let session = session_file::load(&path)?;
        let url = self.url.as_deref().unwrap_or(&session.url);
        AdminClient::new(url, session.access_token)
    }
}
