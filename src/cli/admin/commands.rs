//! `grants`, `sessions` and `audit`: one admin API route each.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::Duration;

use reqwest::Method;
use serde_json::Value;
use uuid::Uuid;

use super::super::{CliError, EXIT_OK};
use super::client::AdminClient;
use super::{AuditCommand, GrantsCommand, SessionsCommand};

/// The admin API's page ceiling (`Page::MAX_LIMIT`).
const USERS_PAGE: usize = 1000;
/// An export can be long; the read gets its own, generous bound.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(600);
const AUDIT_CALLS: &str = "/admin/v1/audit/calls";

pub async fn grants(command: GrantsCommand) -> Result<u8, CliError> {
    match command {
        GrantsCommand::List {
            target,
            user_id,
            database_id,
            limit,
            offset,
        } => {
            let client = target.client()?;
            let mut query: Vec<(&str, String)> = Vec::new();
            query.extend(user_id.map(|id| ("user_id", id.to_string())));
            query.extend(database_id.map(|id| ("database_id", id.to_string())));
            query.extend(limit.map(|n| ("limit", n.to_string())));
            query.extend(offset.map(|n| ("offset", n.to_string())));
            let request = client
                .request(Method::GET, "/admin/v1/grants")
                .query(&query);
            print_json(&client.json("list grants", request).await?)
        }
        GrantsCommand::Apply { target, file } => apply_grants(&target.client()?, &file).await,
    }
}

async fn apply_grants(client: &AdminClient, file: &Path) -> Result<u8, CliError> {
    let raw =
        std::fs::read(file).map_err(|err| CliError::io(format!("read {}", file.display()), err))?;
    let Ok(Value::Array(grants)) = serde_json::from_slice::<Value>(&raw) else {
        return Err(CliError::Invalid(format!(
            "{} must hold a JSON array of grant objects",
            file.display()
        )));
    };
    for (index, grant) in grants.iter().enumerate() {
        let request = client.request(Method::POST, "/admin/v1/grants").json(grant);
        let created = client.json(&format!("grant #{index}"), request).await?;
        println!(
            "created grant {} (#{index})",
            created["id"].as_str().unwrap_or("?")
        );
    }
    Ok(EXIT_OK)
}

pub async fn sessions(command: SessionsCommand) -> Result<u8, CliError> {
    let SessionsCommand::Revoke { target, user } = command;
    let client = target.client()?;
    let id = match Uuid::parse_str(&user) {
        Ok(id) => id,
        Err(_) => find_user(&client, &user).await?,
    };
    let request = client.request(
        Method::POST,
        &format!("/admin/v1/users/{id}/revoke-sessions"),
    );
    print_json(&client.json("revoke sessions", request).await?)
}

/// Page through `/admin/v1/users` for an exact `user_sub` or email match.
async fn find_user(client: &AdminClient, user: &str) -> Result<Uuid, CliError> {
    for page in 0.. {
        let offset = (page * USERS_PAGE).to_string();
        let request = client
            .request(Method::GET, "/admin/v1/users")
            .query(&[("limit", USERS_PAGE.to_string()), ("offset", offset)]);
        let Value::Array(users) = client.json("list users", request).await? else {
            return Err(CliError::Invalid(
                "/admin/v1/users did not return a list".into(),
            ));
        };
        let found = users.iter().find(|row| {
            row["user_sub"].as_str() == Some(user)
                || row["user_email"]
                    .as_str()
                    .is_some_and(|email| email.eq_ignore_ascii_case(user))
        });
        if let Some(id) = found.and_then(|row| row["id"].as_str()) {
            return Uuid::parse_str(id)
                .map_err(|_| CliError::Invalid("/admin/v1/users returned a bad id".into()));
        }
        if users.len() < USERS_PAGE {
            break;
        }
    }
    Err(CliError::Invalid(format!(
        "no user with id, user_sub or email `{user}`"
    )))
}

pub async fn audit(command: AuditCommand) -> Result<u8, CliError> {
    match command {
        AuditCommand::Query { target, params } => {
            let client = target.client()?;
            let request = client.request(Method::GET, AUDIT_CALLS).query(&params);
            let body = client
                .send("query the audit log", request)
                .await?
                .text()
                .await
                .map_err(|err| CliError::unreachable(client.base(), &err))?;
            print!("{body}");
            Ok(EXIT_OK)
        }
        AuditCommand::Export {
            target,
            params,
            out,
        } => export(&target.client()?, &params, &out).await,
    }
}

/// Streamed chunk by chunk: an export can be larger than memory should hold.
/// Owner-only, like the session file — audit rows carry identities and SQL.
async fn export(
    client: &AdminClient,
    params: &[(String, String)],
    out: &Path,
) -> Result<u8, CliError> {
    let request = client
        .request(Method::GET, AUDIT_CALLS)
        .query(params)
        .timeout(EXPORT_TIMEOUT);
    let mut response = client.send("export the audit log", request).await?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|err| CliError::io(format!("create {}", out.display()), err))?;
    let mut bytes = 0usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| CliError::unreachable(client.base(), &err))?
    {
        file.write_all(&chunk)
            .map_err(|err| CliError::io(format!("write {}", out.display()), err))?;
        bytes += chunk.len();
    }
    println!("exported {bytes} bytes to {}", out.display());
    Ok(EXIT_OK)
}

fn print_json(value: &Value) -> Result<u8, CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| CliError::io("encode the response", std::io::Error::other(err)))?;
    println!("{text}");
    Ok(EXIT_OK)
}
