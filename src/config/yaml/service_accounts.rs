//! `service_accounts:` checks: name shape, group cross-reference, the admin
//! gate, and per-account limits.

use std::collections::HashSet;

use crate::config::schema::ServiceAccount;

use super::{AdminConfig, ConfigFileError};

pub(super) fn validate_service_accounts(
    accounts: &[ServiceAccount],
    group_names: &HashSet<&str>,
    admin: &AdminConfig,
) -> Result<(), ConfigFileError> {
    let mut service_names: HashSet<&str> = HashSet::new();
    for account in accounts {
        validate_service_name(&account.name)?;
        if !service_names.insert(account.name.as_str()) {
            return Err(ConfigFileError::Invalid(format!(
                "duplicate service account name `{}`",
                account.name
            )));
        }
        if account.group.trim().is_empty() {
            return Err(ConfigFileError::Invalid(format!(
                "service account `{}` must name a permissions group",
                account.name
            )));
        }
        // A token whose group has no `permissions:` block is almost always
        // a typo'd group name; it would authenticate cleanly and then
        // silently reach nothing. Same fail-fast rule as grants on unknown
        // servers.
        if !group_names.contains(account.group.as_str()) {
            return Err(ConfigFileError::Invalid(format!(
                "service account `{}` maps to group `{}`, which has no `permissions:` \
                 block — declare the group there first (an empty `grants:` list \
                 recognizes the group while granting nothing)",
                account.name, account.group
            )));
        }
        if account.max_concurrent_requests == Some(0) {
            return Err(ConfigFileError::Invalid(format!(
                "service account `{}` has `max_concurrent_requests: 0`, which admits \
                 no request; omit it for the per-identity default or set a positive value",
                account.name
            )));
        }
        // The admin middleware gates on group membership alone, so this
        // boot gate is what keeps a service token off `/admin/*` without
        // widening that middleware. Rejected at boot, not trusted to review.
        if let AdminConfig::Enabled { group, .. } = admin
            && account.group == group.as_str()
        {
            return Err(ConfigFileError::Invalid(format!(
                "service account `{}` maps to group `{}`, which is the admin group — \
                 a service token must never authorize `/admin/*`; give the service \
                 its own group",
                account.name, account.group
            )));
        }
    }
    Ok(())
}

/// Service-account names land in audit fields (`service:<name>` sub,
/// `<name>@service-accounts.invalid` email), so keep them DNS-label-shaped:
/// lowercase alphanumerics and dashes, starting with an alphanumeric, 63 max.
/// Anything fancier buys nothing and makes audit queries/noising regexes
/// messier.
fn validate_service_name(name: &str) -> Result<(), ConfigFileError> {
    let valid = !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
    if valid {
        return Ok(());
    }
    Err(ConfigFileError::Invalid(format!(
        "service account name `{name}` must match ^[a-z0-9][a-z0-9-]{{0,62}}$ \
         (lowercase; it becomes the audit identity `service:{name}`)"
    )))
}
