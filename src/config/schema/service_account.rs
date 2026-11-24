//! `service_accounts[]` as written: `token:` xor a non-empty `tokens:`.

use serde::Deserialize;

use super::super::secret::Password;
use super::ServiceAccount;

/// Converted by [`ServiceAccountSpec::into_account`] at the parse edge rather
/// than through `serde(try_from)`: a deserialize error is reduced to its
/// location (the parser never echoes config text), which would drop the rule
/// the operator broke.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceAccountSpec {
    name: String,
    group: String,
    #[serde(default)]
    token: Option<Password>,
    #[serde(default)]
    tokens: Option<Vec<Password>>,
    #[serde(default)]
    max_concurrent_requests: Option<u32>,
    #[serde(default)]
    require_upstream: bool,
}

impl ServiceAccountSpec {
    /// The account, or the shape rule it breaks (names the account, never a
    /// token).
    pub(crate) fn into_account(self) -> Result<ServiceAccount, String> {
        let tokens = match (self.token, self.tokens) {
            (Some(token), None) => vec![token],
            (None, Some(tokens)) if !tokens.is_empty() => tokens,
            (None, Some(_)) => {
                return Err(format!(
                    "service account `{}`: `tokens:` must list at least one token",
                    self.name
                ));
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "service account `{}`: set `token:` or `tokens:`, not both",
                    self.name
                ));
            }
            (None, None) => {
                return Err(format!(
                    "service account `{}`: `token:` (or `tokens:`) is required",
                    self.name
                ));
            }
        };
        Ok(ServiceAccount {
            name: self.name,
            group: self.group,
            tokens,
            max_concurrent_requests: self.max_concurrent_requests,
            require_upstream: self.require_upstream,
        })
    }
}
