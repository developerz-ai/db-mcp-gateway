//! Role-name checks: identifier shape and the stock-superuser boot gate.

use crate::config::schema::ServerKind;

use super::ConfigFileError;

/// The stock superuser/root account each backend ships with. Connecting as one
/// defeats the whole per-database least-privilege model — the gateway's
/// read-only guarantee then rests entirely on the SQL guard, with no
/// defense-in-depth underneath it, and a guard escape becomes a full compromise
/// of the target. CLAUDE.md states it flatly: "Never run as DB superuser.
/// Per-DB read-only roles, full stop." Rejected at boot rather than trusted to
/// review (#136).
///
/// This matches on the stock *name*, not on actual privilege — a superuser
/// renamed to `app` still passes, and this check can't see the grants behind
/// it. It closes the overwhelmingly common case (someone points the gateway at
/// the account their DB shipped with); the real guarantee remains the
/// least-privilege role the operator provisions target-side.
fn stock_superuser_roles(kind: ServerKind) -> &'static [&'static str] {
    match kind {
        ServerKind::Postgres => &["postgres"],
        ServerKind::Mysql => &["root"],
        ServerKind::Mssql => &["sa"],
        ServerKind::Mongo => &["root", "admin"],
    }
}

pub(super) fn reject_superuser_role(
    role: &str,
    kind: ServerKind,
    db_name: &str,
    server_name: &str,
) -> Result<(), ConfigFileError> {
    // Role names are case-insensitive in practice across these backends, and an
    // operator writing `Postgres` means the same account as `postgres`.
    let lowered = role.to_ascii_lowercase();
    if stock_superuser_roles(kind).contains(&lowered.as_str()) {
        return Err(ConfigFileError::StockSuperuserRole {
            role: role.to_string(),
            kind,
            db_name: db_name.to_string(),
            server_name: server_name.to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_role(role: &str) -> Result<(), String> {
    // Per spec 08: `^[a-zA-Z_][a-zA-Z0-9_]*$`. Catch role typos at boot rather
    // than as cryptic connection failures later.
    let mut chars = role.chars();
    let first = chars.next().ok_or_else(|| "empty role name".to_string())?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!(
            "role `{role}` must start with a letter or underscore"
        ));
    }
    for ch in chars {
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            return Err(format!(
                "role `{role}` contains invalid char `{ch}` (allowed: alphanumerics + underscore)"
            ));
        }
    }
    Ok(())
}
