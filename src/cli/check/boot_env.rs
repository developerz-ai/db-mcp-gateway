//! The environment boot parses, run through boot's own parsers: every
//! variable SET to a value boot would refuse, by name only — never the value.
//!
//! A required variable left unset (`OIDC_ISSUER`, the TLS paths) and a cert
//! file not mounted are not reported: `--check` runs in CI without the
//! deployment's environment. The session signing key's strength is not
//! judged either: it is a secret, checked only by boot.

use std::env::VarError;

use db_mcp_gateway::auth::{AuthConfig, LoginOptions};
use db_mcp_gateway::config::{Config, bool_flag_from_env};
use db_mcp_gateway::exec::pg::init_cancel_pool_size_from_env;
use db_mcp_gateway::transport::client_ip::TrustedProxies;
use db_mcp_gateway::transport::origin::AllowedOrigins;

use crate::startup::connect_budget_from_env;

/// The `LoginOptions` variables, each parsed alone so one bad value does not
/// hide another.
const LOGIN_OPTION_VARS: [&str; 5] = [
    "OIDC_SCOPES",
    "OIDC_GROUPS_PREFIX",
    "OIDC_TOKEN_AUTH_METHOD",
    "GROUPS_MAX_AGE",
    "GATEWAY_SUPPORT_CONTACT",
];

/// Every invalid variable, in boot's reading order.
pub fn invalid_variables() -> Vec<&'static str> {
    let config_errors = Config::env_errors();
    let mut names: Vec<&'static str> = config_errors
        .iter()
        .filter(|err| !err.is_deployment_only())
        .map(|err| err.variable())
        .collect();
    if AuthConfig::session_ttl_from_env().is_err() {
        names.push("SESSION_TTL_HOURS");
    }
    if AuthConfig::refresh_ttl_from_env().is_err() {
        names.push("REFRESH_TTL_DAYS");
    }
    if let Err(err) = bool_flag_from_env("ALLOW_INSECURE_SIGNING_KEY") {
        names.push(err.var);
    }
    names.extend(
        LOGIN_OPTION_VARS
            .into_iter()
            .filter(|var| !login_option_valid(var)),
    );
    if std::env::var("TRUSTED_PROXIES").is_ok_and(|raw| TrustedProxies::parse(&raw).is_err()) {
        names.push("TRUSTED_PROXIES");
    }
    // Loopback-ness of the bind only widens what is accepted at request
    // time; whether the list parses does not depend on it.
    let bind = Config::default().bind;
    if std::env::var("MCP_ALLOWED_ORIGINS")
        .is_ok_and(|raw| AllowedOrigins::parse(&raw, bind).is_err())
    {
        names.push("MCP_ALLOWED_ORIGINS");
    }
    if init_cancel_pool_size_from_env().is_err() {
        names.push("PG_CANCEL_POOL_SIZE");
    }
    if connect_budget_from_env().is_err() {
        names.push("STATE_DB_CONNECT_TIMEOUT_SECONDS");
    }
    names
}

fn login_option_valid(var: &str) -> bool {
    match std::env::var(var) {
        Ok(value) => LoginOptions::from_lookup(|name| (name == var).then(|| value.clone())).is_ok(),
        Err(VarError::NotPresent) => true,
        Err(VarError::NotUnicode(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-kept login list stays inside the documented env table.
    #[test]
    fn login_option_vars_are_known_env() {
        for var in LOGIN_OPTION_VARS {
            assert!(super::super::env_names::KNOWN_ENV.contains(&var), "{var}");
        }
    }
}
