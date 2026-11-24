//! `permissions:` — who (a group or one user) holds which grants.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::{Action, Constraints};

/// Who a `permissions:` block applies to. YAML names exactly one of `group:`
/// (an IdP group claim) or `user:` (one SSO subject).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subject {
    Group(String),
    /// Matches an SSO session whose `sub` equals this value — never a
    /// service identity, whose authority is exactly its one group (spec 14).
    User(String),
}

impl Subject {
    pub fn name(&self) -> &str {
        match self {
            Self::Group(name) | Self::User(name) => name,
        }
    }

    /// Strip stray YAML whitespace: both are compared to IdP claims verbatim.
    pub fn trim(&mut self) {
        let (Self::Group(name) | Self::User(name)) = self;
        *name = name.trim().to_string();
    }
}

/// `group `ops`` / `user `sub-1`` — the noun boot errors name a block by.
impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Group(name) => write!(f, "group `{name}`"),
            Self::User(name) => write!(f, "user `{name}`"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "PermissionSpec")]
pub struct Permission {
    pub subject: Subject,
    pub grants: Vec<Grant>,
}

impl Permission {
    /// The group a group block names; `None` for a `user:` block.
    pub fn group(&self) -> Option<&str> {
        match &self.subject {
            Subject::Group(name) => Some(name),
            Subject::User(_) => None,
        }
    }
}

/// The block as written: `group:` and `user:` are both optional here so the
/// exactly-one rule can produce its own error. `RawConfigFile` converts these
/// itself, because a parse error drops its message (it could quote the file).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PermissionSpec {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    grants: Vec<Grant>,
}

impl TryFrom<PermissionSpec> for Permission {
    type Error = String;

    fn try_from(spec: PermissionSpec) -> Result<Self, String> {
        let subject = match (spec.group, spec.user) {
            (Some(group), None) => Subject::Group(group),
            (None, Some(user)) => Subject::User(user),
            _ => {
                return Err(
                    "a permissions entry names exactly one of `group:` or `user:`".to_string(),
                );
            }
        };
        Ok(Self {
            subject,
            grants: spec.grants,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub server: String,
    pub database: String,
    pub action: Action,
    /// Per-grant constraints layered on top of the action. Optional in YAML;
    /// `authz::evaluate` merges these most-restrictively across all matching
    /// grants (spec 06 §Evaluation). A `profile:` is folded in at parse time.
    #[serde(default)]
    pub constraints: Constraints,
    /// Databases a `database: "*"` grant does not cover. Boot rejects it on
    /// a grant naming one database.
    #[serde(default)]
    pub except: Vec<String>,
    /// A `constraint_profiles:` entry merged (most restrictive) into
    /// `constraints` when the config is parsed; kept for display.
    #[serde(default)]
    pub profile: Option<String>,
    /// DB grants only (`permissions_grants.expires_at`); YAML grants never
    /// expire. Evaluation ignores a grant at or past this instant.
    #[serde(skip)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl Grant {
    /// A non-expiring grant with no `except:` and no profile.
    pub fn new(server: &str, database: &str, action: Action, constraints: Constraints) -> Self {
        Self {
            server: server.to_string(),
            database: database.to_string(),
            action,
            constraints,
            except: Vec::new(),
            profile: None,
            expires_at: None,
        }
    }

    /// Whether the grant's database pattern covers `database` — the literal
    /// name, or `*` minus its `except:` list.
    pub fn covers_database(&self, database: &str) -> bool {
        if self.database == "*" {
            return !self.except.iter().any(|e| e == database);
        }
        self.database == database
    }

    /// Not yet expired at `now`. The instant `expires_at` itself is expired.
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|at| now < at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Permission, serde_saphyr::Error> {
        serde_saphyr::from_str_with_options(yaml, crate::config::yaml::non_leaking_options())
    }

    #[test]
    fn group_and_user_blocks_parse_and_both_or_neither_is_rejected() {
        let group = parse("group: ops\ngrants: []\n").unwrap();
        assert_eq!(group.subject, Subject::Group("ops".into()));
        assert_eq!(group.group(), Some("ops"));
        let user = parse("user: sub-1\n").unwrap();
        assert_eq!(user.subject, Subject::User("sub-1".into()));
        assert_eq!(user.group(), None);
        for bad in ["grants: []\n", "group: a\nuser: b\n"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse("group: a\ngrups: []\n").is_err(), "typo guard kept");
    }

    #[test]
    fn except_covers_everything_but_the_listed_databases() {
        let mut grant = Grant::new("s", "*", Action::QueryRead, Constraints::default());
        grant.except = vec!["secrets".into()];
        assert!(grant.covers_database("app"));
        assert!(!grant.covers_database("secrets"));
        let named = Grant::new("s", "app", Action::QueryRead, Constraints::default());
        assert!(named.covers_database("app") && !named.covers_database("other"));
    }

    #[test]
    fn expiry_boundary_is_exclusive() {
        let now = Utc::now();
        let mut grant = Grant::new("s", "*", Action::QueryRead, Constraints::default());
        assert!(grant.is_live_at(now));
        grant.expires_at = Some(now);
        assert!(!grant.is_live_at(now), "expires_at itself is expired");
        assert!(grant.is_live_at(now - chrono::Duration::microseconds(1)));
    }
}
