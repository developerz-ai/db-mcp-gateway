//! `gateway:` — deployment-wide settings, and the `env: production` rule that
//! inline literal secrets never ship.

use serde::Deserialize;

use super::{ConfigFile, ConfigFileError};
use crate::config::secret::Password;

/// Deployment-wide settings. Bind address, state DB and TLS stay env-driven
/// (`GATEWAY_BIND`, `STATE_DB_URL`, `TLS_*`); only what has no env twin lives here.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayBlock {
    #[serde(default)]
    pub env: Environment,
}

/// `production` rejects inline literal secrets at boot; `development` (the
/// default, so local configs keep working) tolerates them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    #[default]
    Development,
    Production,
}

impl ConfigFile {
    /// Spec 05: a literal password or token in a production config is a secret
    /// committed to whatever repo holds the YAML. Names the field, never the value.
    pub(super) fn reject_production_literals(&self) -> Result<(), ConfigFileError> {
        if self.gateway.env != Environment::Production {
            return Ok(());
        }
        for server in &self.servers {
            for db in &server.databases {
                if matches!(db.password, Password::Literal(_)) {
                    return Err(literal_error(format!(
                        "servers[{}].databases[{}].password",
                        server.name, db.name
                    )));
                }
                if matches!(db.write_password, Some(Password::Literal(_))) {
                    return Err(literal_error(format!(
                        "servers[{}].databases[{}].write_password",
                        server.name, db.name
                    )));
                }
            }
        }
        for account in &self.service_accounts {
            if matches!(account.token, Password::Literal(_)) {
                return Err(literal_error(format!(
                    "service_accounts[{}].token",
                    account.name
                )));
            }
        }
        Ok(())
    }
}

fn literal_error(field: String) -> ConfigFileError {
    ConfigFileError::Invalid(format!(
        "{field} is an inline literal, which `gateway.env: production` rejects — \
         use `${{ENV:NAME}}` or `${{FILE:/path}}`"
    ))
}
