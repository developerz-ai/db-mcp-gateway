//! Resolve every secret reference in a parsed config and report each failure
//! with the server/database/tier it belongs to.

use crate::config::secret::{Password, SecretSite, SiteSecretError};

use super::{ConfigFile, ConfigLoadError};

impl ConfigFile {
    /// Boot's twin of [`Self::resolve_secrets`]: tries every reference and
    /// reports all failures, each naming its server/database/tier.
    pub fn resolve_all_secrets(&self) -> Result<(), ConfigLoadError> {
        let errors = self.secret_errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigLoadError::Secrets(errors))
        }
    }

    /// Every secret reference that does not resolve, in file order. Resolved
    /// values are dropped immediately.
    pub fn secret_errors(&self) -> Vec<SiteSecretError> {
        self.secret_refs()
            .filter_map(|(site, password)| {
                password
                    .resolve()
                    .err()
                    .map(|error| SiteSecretError { site, error })
            })
            .collect()
    }

    fn secret_refs(&self) -> impl Iterator<Item = (SecretSite, &Password)> {
        let databases = self.servers.iter().flat_map(|server| {
            server.databases.iter().flat_map(move |db| {
                let read = SecretSite::ReadPassword {
                    server: server.name.clone(),
                    database: db.name.clone(),
                };
                let write = db.write_password.as_ref().map(|password| {
                    let site = SecretSite::WritePassword {
                        server: server.name.clone(),
                        database: db.name.clone(),
                    };
                    (site, password)
                });
                std::iter::once((read, &db.password)).chain(write)
            })
        });
        let tokens = self.service_accounts.iter().flat_map(|account| {
            account.tokens.iter().enumerate().map(|(index, token)| {
                let site = SecretSite::ServiceToken {
                    account: account.name.clone(),
                    index,
                };
                (site, token)
            })
        });
        databases.chain(tokens)
    }
}
