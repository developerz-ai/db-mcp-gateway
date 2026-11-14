//! `admin:` — the raw YAML block and the validated [`AdminConfig`] built from
//! it once, at parse time.

use std::time::Duration;

use serde::Deserialize;

use super::ConfigFileError;

/// Raw YAML shape of `admin:` (spec 12 §"Admin API"). Lives only between
/// deserialization and [`AdminConfig::from_block`]; nothing downstream sees it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminBlock {
    #[serde(default)]
    enabled: bool,
    /// Optional, and ignored, when disabled — so `admin: { enabled: false }`
    /// parses.
    #[serde(default)]
    group: String,
    #[serde(default)]
    session_max_age_secs: Option<u64>,
}

/// Validated `admin:` section. Absent or `enabled: false` → [`Self::Disabled`]
/// and the entire `/admin/*` route returns 404.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AdminConfig {
    #[default]
    Disabled,
    Enabled {
        /// SSO group claim that authorizes `/admin/v1/*` calls.
        group: AdminGroup,
        /// Maximum session age before admin access is denied, regardless of
        /// `session_ttl_hours` — the caller must re-authenticate.
        ///
        /// Group memberships are snapshotted at login, so a user removed from
        /// the admin group in the IdP keeps passing the group check until their
        /// session expires (up to `session_ttl_hours`, default 8 h). This caps
        /// that window: `session_max_age_secs: 3600` means a removed admin can
        /// act for at most one hour before the gateway forces re-login.
        ///
        /// `None` → no age cap; rely on `session_ttl_hours` alone.
        session_max_age: Option<Duration>,
    },
}

impl AdminConfig {
    pub(super) fn from_block(block: Option<AdminBlock>) -> Result<Self, ConfigFileError> {
        match block {
            Some(block) if block.enabled => Ok(Self::Enabled {
                group: AdminGroup::new(block.group)?,
                session_max_age: block.session_max_age_secs.map(Duration::from_secs),
            }),
            Some(_) | None => Ok(Self::Disabled),
        }
    }
}

/// The admin SSO group: never blank, because a blank group would make every
/// authenticated caller an admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminGroup(String);

impl AdminGroup {
    pub fn new(group: impl Into<String>) -> Result<Self, ConfigFileError> {
        let group = group.into();
        if group.trim().is_empty() {
            return Err(ConfigFileError::Invalid(
                "admin.group must be non-empty when admin.enabled is true".to_string(),
            ));
        }
        Ok(Self(group))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
