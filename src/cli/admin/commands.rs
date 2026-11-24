//! `grants`, `sessions` and `audit`: one admin API route each.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::{Method, Response};
use serde_json::Value;
use uuid::Uuid;

use super::super::{CliError, EXIT_OK};
use super::client::AdminClient;
use super::{AuditCommand, GrantsCommand, SessionsCommand, UserField};

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
    let SessionsCommand::Revoke { target, by, user } = command;
    let client = target.client()?;
    let id = find_user(&client, &user, by).await?;
    let request = client.request(
        Method::POST,
        &format!("/admin/v1/users/{id}/revoke-sessions"),
    );
    print_json(&client.json("revoke sessions", request).await?)
}

/// Page through `/admin/v1/users` for exact matches on the selected field
/// (every field when `by` is `None`). A value that names two different users
/// — a UUID-shaped `user_sub` equal to another user's id — is refused rather
/// than guessed.
async fn find_user(
    client: &AdminClient,
    user: &str,
    by: Option<UserField>,
) -> Result<Uuid, CliError> {
    let mut found: Vec<Uuid> = Vec::new();
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
        for row in users.iter().filter(|row| user_matches(row, user, by)) {
            let id = row["id"]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or_else(|| CliError::Invalid("/admin/v1/users returned a bad id".into()))?;
            if !found.contains(&id) {
                found.push(id);
            }
        }
        if users.len() < USERS_PAGE {
            break;
        }
    }
    only_user(&found, user)
}

fn user_matches(row: &Value, user: &str, by: Option<UserField>) -> bool {
    let field = |name: &str| row[name].as_str();
    // As UUIDs: `6F1C…` and `6f1c…` are one id. Subjects stay exact strings.
    let id = || {
        let wanted = Uuid::parse_str(user).ok();
        wanted.is_some() && field("id").and_then(|id| Uuid::parse_str(id).ok()) == wanted
    };
    let sub = || field("user_sub") == Some(user);
    let email = || field("user_email").is_some_and(|email| email.eq_ignore_ascii_case(user));
    match by {
        Some(UserField::Id) => id(),
        Some(UserField::Sub) => sub(),
        Some(UserField::Email) => email(),
        None => id() || sub() || email(),
    }
}

fn only_user(found: &[Uuid], user: &str) -> Result<Uuid, CliError> {
    match found {
        [id] => Ok(*id),
        [] => Err(CliError::Invalid(format!(
            "no user with id, user_sub or email `{user}`"
        ))),
        _ => Err(CliError::Invalid(format!(
            "`{user}` matches {} users; pick one with --by id|sub|email",
            found.len()
        ))),
    }
}

pub async fn audit(command: AuditCommand) -> Result<u8, CliError> {
    match command {
        AuditCommand::Query { target, params } => {
            let client = target.client()?;
            let request = client.request(Method::GET, AUDIT_CALLS).query(&params);
            let response = client.send("query the audit log", request).await?;
            copy_body(
                &client,
                response,
                &mut std::io::stdout().lock(),
                "write stdout",
            )
            .await?;
            Ok(EXIT_OK)
        }
        AuditCommand::Export {
            target,
            params,
            out,
        } => export(&target.client()?, &params, &out).await,
    }
}

/// Streamed into an owner-only temp file beside `out` (audit rows carry
/// identities and SQL), published at `out` only once complete: a failed
/// export leaves nothing at `out` and a retry to the same path works.
async fn export(
    client: &AdminClient,
    params: &[(String, String)],
    out: &Path,
) -> Result<u8, CliError> {
    if out.symlink_metadata().is_ok() {
        return Err(CliError::Invalid(format!(
            "{} already exists",
            out.display()
        )));
    }
    let request = client
        .request(Method::GET, AUDIT_CALLS)
        .query(params)
        .timeout(EXPORT_TIMEOUT);
    let response = client.send("export the audit log", request).await?;
    let temp = partial_path(out);
    let result = write_then_publish(client, response, &temp, out).await;
    // Best effort: whether published (a second link) or failed, the temp
    // name has to go; its contents are owner-only either way.
    let _ = fs::remove_file(&temp);
    let bytes = result?;
    println!("exported {bytes} bytes to {}", out.display());
    Ok(EXIT_OK)
}

async fn write_then_publish(
    client: &AdminClient,
    response: Response,
    temp: &Path,
    out: &Path,
) -> Result<usize, CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .map_err(|err| CliError::io(format!("create {}", temp.display()), err))?;
    let what = format!("write {}", temp.display());
    let bytes = copy_body(client, response, &mut file, &what).await?;
    file.sync_all().map_err(|err| CliError::io(what, err))?;
    // A hard link never replaces an existing `out`, unlike a rename.
    fs::hard_link(temp, out)
        .map_err(|err| CliError::io(format!("create {}", out.display()), err))?;
    Ok(bytes)
}

fn partial_path(out: &Path) -> PathBuf {
    let name = out
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    out.with_file_name(format!(".{name}.{}.partial", Uuid::new_v4().simple()))
}

/// Chunk by chunk: the body can be larger than memory should hold.
async fn copy_body(
    client: &AdminClient,
    mut response: Response,
    sink: &mut impl Write,
    what: &str,
) -> Result<usize, CliError> {
    let mut bytes = 0usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| CliError::unreachable(client.shown(), &err))?
    {
        sink.write_all(&chunk)
            .map_err(|err| CliError::io(what.to_string(), err))?;
        bytes += chunk.len();
    }
    sink.flush()
        .map_err(|err| CliError::io(what.to_string(), err))?;
    Ok(bytes)
}

fn print_json(value: &Value) -> Result<u8, CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| CliError::io("encode the response", std::io::Error::other(err)))?;
    println!("{text}");
    Ok(EXIT_OK)
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod tests;
