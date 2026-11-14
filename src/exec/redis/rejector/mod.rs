//! Read-only enforcement for Redis commands: a deny-by-default allowlist,
//! checked before any network call. Defense in depth on top of the
//! operator's least-privilege ACL user — the ACL is the primary guardrail.
//!
//! Security-required (CLAUDE.md). The command arrives in `run_query`'s `sql`
//! field as a JSON array argv, e.g. `["HGETALL","user:1"]`. Elements are
//! strings; numbers are accepted and sent as their decimal text. The first
//! element is the command name, matched case-insensitively against
//! [`ALLOWED_COMMANDS`]. Everything else — writes, `KEYS`, `SORT`, scripting,
//! blocking pops, `SELECT`, `CLIENT`, `CONFIG`, `MULTI`, module commands — is
//! refused.
//!
//! The `*SCAN` family is the one place the rejector rewrites the argv: its
//! `COUNT` hint is clamped to [`MAX_SCAN_COUNT`] (and injected when absent),
//! so one call cannot ask the server to walk an unbounded slice of the
//! keyspace. Every other bound depends on the call's row limit and is
//! applied when the command runs (`super::bounded`).

use serde_json::Value;

use super::shape::Shape;

/// Read-only commands the gateway forwards. Upper case: the canonical form
/// the argv's first element is matched against and sent as.
const ALLOWED_COMMANDS: &[&str] = &[
    // strings + generic keyspace reads
    "GET",
    "MGET",
    "STRLEN",
    "GETRANGE",
    "SUBSTR",
    "GETBIT",
    "BITCOUNT",
    "BITPOS",
    "EXISTS",
    "TYPE",
    "TTL",
    "PTTL",
    "EXPIRETIME",
    "PEXPIRETIME",
    "DBSIZE",
    // hashes
    "HGET",
    "HMGET",
    "HGETALL",
    "HKEYS",
    "HVALS",
    "HLEN",
    "HEXISTS",
    "HSTRLEN",
    "HRANDFIELD",
    "HSCAN",
    // lists
    "LRANGE",
    "LLEN",
    "LINDEX",
    "LPOS",
    // sets
    "SMEMBERS",
    "SISMEMBER",
    "SMISMEMBER",
    "SCARD",
    "SRANDMEMBER",
    "SSCAN",
    "SINTER",
    "SUNION",
    "SDIFF",
    "SINTERCARD",
    // sorted sets
    "ZRANGE",
    "ZRANGEBYSCORE",
    "ZRANGEBYLEX",
    "ZREVRANGE",
    "ZREVRANGEBYSCORE",
    "ZREVRANGEBYLEX",
    "ZSCORE",
    "ZMSCORE",
    "ZCARD",
    "ZCOUNT",
    "ZLEXCOUNT",
    "ZRANK",
    "ZREVRANK",
    "ZRANDMEMBER",
    "ZSCAN",
    // streams
    "XRANGE",
    "XREVRANGE",
    "XLEN",
    // keyspace iteration
    "SCAN",
];

/// Ceiling on a `*SCAN` call's `COUNT` hint, and the value injected when the
/// caller gives none.
pub const MAX_SCAN_COUNT: u32 = 1000;

/// Longest command name echoed back in a rejection; the rest is cut.
const MAX_ECHOED_NAME_CHARS: usize = 32;

/// One accepted command: its canonical name, the arguments to send (with any
/// gateway rewrite applied) and the result shape it answers in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub name: &'static str,
    pub args: Vec<String>,
    pub shape: Shape,
}

/// Why a command was refused. `Display` is agent-facing; it names the
/// command or option but never echoes an argument value.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RejectReason {
    #[error("redis command must be a JSON array of strings, e.g. [\"GET\",\"key\"]")]
    Malformed,

    #[error("redis command array is empty")]
    EmptyCommand,

    #[error("redis command argument {0} is not a string or number")]
    NonStringArgument(usize),

    #[error("redis command `{0}` is not in the read-only allowlist")]
    DisallowedCommand(String),

    #[error("redis command `{command}` does not allow option `{option}`")]
    DisallowedOption {
        command: &'static str,
        option: String,
    },

    #[error("redis command `{command}` is missing {what}")]
    MissingArgument {
        command: &'static str,
        what: &'static str,
    },

    #[error("redis command `{0}` needs COUNT to be a positive integer")]
    InvalidCount(&'static str),

    #[error("redis command `{0}` needs its count to be an integer")]
    NonIntegerCount(&'static str),
}

impl RejectReason {
    /// The argv itself is not well formed (as opposed to well formed but
    /// refused by policy). The tool layer answers these `invalid_arguments`.
    pub fn is_malformed(&self) -> bool {
        matches!(
            self,
            Self::Malformed
                | Self::EmptyCommand
                | Self::NonStringArgument(_)
                | Self::MissingArgument { .. }
                | Self::InvalidCount(_)
                | Self::NonIntegerCount(_)
        )
    }
}

/// Parse and police one argv. `Ok` carries the command to send — never the
/// raw input, so the `COUNT` clamp cannot be skipped.
pub fn validate_command(json: &str) -> Result<Command, RejectReason> {
    let items: Vec<Value> = serde_json::from_str(json).map_err(|_| RejectReason::Malformed)?;
    let mut argv = items
        .into_iter()
        .enumerate()
        .map(|(index, item)| match item {
            Value::String(s) => Ok(s),
            Value::Number(n) => Ok(n.to_string()),
            _ => Err(RejectReason::NonStringArgument(index)),
        })
        .collect::<Result<Vec<String>, _>>()?;
    if argv.is_empty() {
        return Err(RejectReason::EmptyCommand);
    }
    let requested = argv.remove(0);
    let name = canonical_name(&requested)
        .ok_or_else(|| RejectReason::DisallowedCommand(echoed_name(&requested)))?;
    let mut args = argv;
    let shape = match name {
        "SCAN" => scan_options(name, &mut args, 1, true)?,
        "SSCAN" | "HSCAN" | "ZSCAN" => scan_options(name, &mut args, 2, false)?,
        "HRANDFIELD" | "SRANDMEMBER" | "ZRANDMEMBER" => {
            // The executor clamps the count; it must be a number to clamp.
            if args
                .get(1)
                .is_some_and(|count| count.parse::<i64>().is_err())
            {
                return Err(RejectReason::NonIntegerCount(name));
            }
            Shape::for_command(name, &args)
        }
        _ => Shape::for_command(name, &args),
    };
    Ok(Command { name, args, shape })
}

fn canonical_name(requested: &str) -> Option<&'static str> {
    ALLOWED_COMMANDS
        .iter()
        .copied()
        .find(|allowed| allowed.eq_ignore_ascii_case(requested))
}

fn echoed_name(requested: &str) -> String {
    requested.chars().take(MAX_ECHOED_NAME_CHARS).collect()
}

/// Walk a `*SCAN` call's options after its `fixed` leading arguments (the
/// cursor, and the key for `SSCAN`/`HSCAN`/`ZSCAN`): `MATCH <pattern>`,
/// `COUNT <n>` and, for `SCAN` only, `TYPE <type>`. Every `COUNT` is clamped
/// (Redis honours the last one, so clamping only the first would not do),
/// and one is appended when none was given. `HSCAN`'s `NOVALUES` is refused:
/// it would change the reply's shape.
fn scan_options(
    command: &'static str,
    args: &mut Vec<String>,
    fixed: usize,
    allow_type: bool,
) -> Result<Shape, RejectReason> {
    if args.len() < fixed {
        return Err(RejectReason::MissingArgument {
            command,
            what: if fixed == 1 {
                "a cursor"
            } else {
                "a key and a cursor"
            },
        });
    }
    let mut saw_count = false;
    let mut index = fixed;
    while index < args.len() {
        let option = args[index].to_ascii_uppercase();
        let known =
            matches!(option.as_str(), "MATCH" | "COUNT") || (allow_type && option == "TYPE");
        if !known {
            return Err(RejectReason::DisallowedOption {
                command,
                option: echoed_name(&args[index]),
            });
        }
        let Some(value) = args.get_mut(index + 1) else {
            return Err(RejectReason::MissingArgument {
                command,
                what: "an option value",
            });
        };
        if option == "COUNT" {
            let count: u32 = value
                .parse()
                .ok()
                .filter(|n| *n > 0)
                .ok_or(RejectReason::InvalidCount(command))?;
            *value = count.min(MAX_SCAN_COUNT).to_string();
            saw_count = true;
        }
        index += 2;
    }
    if !saw_count {
        args.push("COUNT".to_string());
        args.push(MAX_SCAN_COUNT.to_string());
    }
    Ok(Shape::for_command(command, args))
}

#[cfg(test)]
mod tests;
