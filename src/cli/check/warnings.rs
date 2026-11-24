//! What `--check` warns about: a config that boots but does not do what it
//! reads like. None of these stop boot.

use std::collections::BTreeSet;

use db_mcp_gateway::config::{Action, ConfigFile, Password, ServerKind, Tls};

use super::env_names::{GATEWAY_ENV_PREFIXES, KNOWN_ENV};

pub fn collect(config: &ConfigFile, env: &[String]) -> Vec<String> {
    let mut warnings = tls_warnings(config);
    warnings.extend(inert_constraints(config));
    warnings.extend(unknown_env(config, env));
    warnings
}

/// Postgres `tls: required` encrypts without verifying the server certificate
/// (`sslmode=require`; Mongo's and Redis' `required` do verify), and
/// `tls: insecure` is plaintext. Boot logs the same lines.
pub fn tls_warnings(config: &ConfigFile) -> Vec<String> {
    config
        .servers
        .iter()
        .filter_map(|server| match (server.kind, server.tls) {
            (ServerKind::Postgres, Tls::Required) => Some(format!(
                "server `{}`: target TLS is encrypted but the server certificate is NOT verified \
                 (set `tls: verify_full`)",
                server.name
            )),
            (_, Tls::Insecure) => Some(format!(
                "server `{}`: target TLS is disabled; credentials and results cross the network \
                 in plaintext",
                server.name
            )),
            _ => None,
        })
        .collect()
}

/// A constraint the tools its action unlocks never read: `describe_schema`
/// ignores a grant's `row_limit`, and `get_query_history` reads the gateway's
/// own audit log, so neither bound reaches a target.
fn inert_constraints(config: &ConfigFile) -> Vec<String> {
    let mut warnings = Vec::new();
    for permission in &config.permissions {
        for grant in &permission.grants {
            let constraints = &grant.constraints;
            let inert: &[(&str, bool)] = match grant.action {
                Action::SchemaRead => &[("row_limit", constraints.row_limit.is_some())],
                Action::HistoryRead => &[
                    ("row_limit", constraints.row_limit.is_some()),
                    (
                        "statement_timeout_ms",
                        constraints.statement_timeout_ms.is_some(),
                    ),
                ],
                Action::QueryRead | Action::QueryWrite => &[],
            };
            for (field, _) in inert.iter().filter(|(_, set)| *set) {
                warnings.push(format!(
                    "permission {} grant on `{}`/`{}`: `{field}` has no effect on a \
                     `{}` grant",
                    permission.subject,
                    grant.server,
                    grant.database,
                    action_name(grant.action)
                ));
            }
        }
    }
    warnings
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::SchemaRead => "schema_read",
        Action::QueryRead => "query_read",
        Action::QueryWrite => "query_write",
        Action::HistoryRead => "history_read",
    }
}

/// A variable that looks like one of the gateway's (shares a prefix with
/// one) but is not one is most likely a typo, and the setting it was meant
/// for silently keeps its default. Names only; values are never read.
fn unknown_env(config: &ConfigFile, env: &[String]) -> Vec<String> {
    let referenced = referenced_env(config);
    let mut names: Vec<&String> = env.iter().collect();
    names.sort();
    names
        .into_iter()
        .filter(|name| !KNOWN_ENV.contains(&name.as_str()) && !referenced.contains(name.as_str()))
        .filter_map(|name| {
            let prefix = GATEWAY_ENV_PREFIXES
                .iter()
                .find(|prefix| name.starts_with(*prefix))?;
            let siblings: Vec<&str> = KNOWN_ENV
                .iter()
                .copied()
                .filter(|known| known.starts_with(prefix))
                .collect();
            Some(format!(
                "env `{name}` is set but the gateway reads no such variable (known: {})",
                siblings.join(", ")
            ))
        })
        .collect()
}

/// `${ENV:…}` names the config itself reads: operator-chosen, so never typos.
fn referenced_env(config: &ConfigFile) -> BTreeSet<&str> {
    let databases = config.servers.iter().flat_map(|server| {
        server
            .databases
            .iter()
            .flat_map(|db| std::iter::once(&db.password).chain(db.write_password.as_ref()))
    });
    let tokens = config
        .service_accounts
        .iter()
        .flat_map(|account| account.tokens.iter());
    databases
        .chain(tokens)
        .filter_map(|password| match password {
            Password::EnvVar(name) => Some(name.as_str()),
            _ => None,
        })
        .collect()
}
