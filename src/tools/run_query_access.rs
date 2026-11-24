//! The access a `run_query` statement needs, checked at the tool edge per
//! server kind: a statement the gateway refuses never reaches the pool.

use serde_json::Value;

use crate::exec::mongo::rejector as mongo_rejector;
use crate::exec::redis::rejector as redis_rejector;
use crate::exec::{Access, GuardedSql};

use crate::tools::audit_dispatch::{
    Outcome, OutcomeCode, error_outcome, guard_rejected, invalid_arguments,
};

/// The access `sql` needs, after the guard at the caller's grant level:
/// `ReadWrite` only for a data write under a `query_write` grant.
pub(super) fn statement_access(sql: &str, writes_allowed: bool) -> Result<Access, Box<Outcome>> {
    let grant = if writes_allowed {
        Access::ReadWrite
    } else {
        Access::ReadOnly
    };
    GuardedSql::parse(sql, grant)
        .map(|guarded| guarded.required_access())
        .map_err(|err| Box::new(guard_rejected(&err)))
}

/// The Redis rejector, run at the tool edge: a malformed argv is the
/// caller's argument error, a well-formed but refused command `forbidden_sql`.
/// `RedisAdapter::execute` runs the same check again before any network call.
pub(super) fn redis_access(id: Value, argv: &str) -> Result<Access, Box<Outcome>> {
    match redis_rejector::validate_command(argv) {
        Ok(_) => Ok(Access::ReadOnly),
        Err(err) if err.is_malformed() => {
            Err(Box::new(invalid_arguments(id, &format!("`sql`: {err}"))))
        }
        Err(err) => Err(Box::new(error_outcome(
            OutcomeCode::ForbiddenSql,
            &format!("command rejected by gateway: {err}"),
        ))),
    }
}

/// A Mongo command that is not a JSON object naming a command is the
/// caller's argument error. A well-formed command the policy refuses is left
/// to `MongoAdapter::execute`, which refuses it `forbidden_sql`.
pub(super) fn mongo_access(id: Value, command: &str) -> Result<Access, Box<Outcome>> {
    match mongo_rejector::validate_command(command) {
        Err(err) if err.is_malformed() => {
            Err(Box::new(invalid_arguments(id, &format!("`sql`: {err}"))))
        }
        _ => Ok(Access::ReadOnly),
    }
}
