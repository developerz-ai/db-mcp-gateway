//! `constraint_profiles:` — named constraint sets a grant references with
//! `profile: <name>`, folded into the grant when the config is parsed.

use std::collections::BTreeMap;

use super::{Constraints, Permission};

/// `constraint_profiles:` as written: name → constraints.
pub type ConstraintProfiles = BTreeMap<String, Constraints>;

/// Fold each grant's `profile:` into its `constraints` with the authz merge,
/// so the most restrictive of the profile and the grant's own values wins —
/// a profile can tighten a grant, never loosen it. Evaluation then sees only
/// plain constraints. An unknown profile name is a boot error.
pub fn apply_constraint_profiles(
    profiles: &ConstraintProfiles,
    permissions: &mut [Permission],
) -> Result<(), String> {
    for permission in permissions {
        let subject = permission.subject.clone();
        for grant in &mut permission.grants {
            let Some(name) = &grant.profile else {
                continue;
            };
            let profile = profiles.get(name).ok_or_else(|| {
                format!(
                    "permission {subject} grant on `{}`/`{}` names unknown constraint \
                     profile `{name}`; declare it under `constraint_profiles:`",
                    grant.server, grant.database
                )
            })?;
            grant.constraints = crate::authz::merge(profile, &grant.constraints);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Action, Grant, Subject};

    fn block(profile: Option<&str>, constraints: Constraints) -> Vec<Permission> {
        let mut grant = Grant::new("s", "*", Action::QueryRead, constraints);
        grant.profile = profile.map(str::to_string);
        vec![Permission {
            subject: Subject::Group("g".into()),
            grants: vec![grant],
        }]
    }

    #[test]
    fn profile_merges_most_restrictive_with_inline_values() {
        let profiles = ConstraintProfiles::from([(
            "strict".to_string(),
            Constraints {
                require_reason: true,
                row_limit: Some(100),
                statement_timeout_ms: Some(5_000),
            },
        )]);
        let mut perms = block(
            Some("strict"),
            Constraints {
                row_limit: Some(10),
                statement_timeout_ms: Some(60_000),
                ..Constraints::default()
            },
        );
        apply_constraint_profiles(&profiles, &mut perms).unwrap();
        assert_eq!(
            perms[0].grants[0].constraints,
            Constraints {
                require_reason: true,
                row_limit: Some(10),
                statement_timeout_ms: Some(5_000),
            }
        );
    }

    #[test]
    fn unknown_profile_is_rejected_and_no_profile_is_untouched() {
        let mut perms = block(Some("nope"), Constraints::default());
        let err = apply_constraint_profiles(&ConstraintProfiles::new(), &mut perms).unwrap_err();
        assert!(err.contains("unknown constraint profile `nope`"), "{err}");
        let mut plain = block(None, Constraints::default());
        apply_constraint_profiles(&ConstraintProfiles::new(), &mut plain).unwrap();
        assert_eq!(plain[0].grants[0].constraints, Constraints::default());
    }
}
