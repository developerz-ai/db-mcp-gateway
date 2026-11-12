//! `ConfigFileError` and the parser-message filtering that keeps config
//! bytes out of it.

use std::path::PathBuf;

use crate::config::schema::ServerKind;

#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    #[error("failed to read config file `{path}`")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Carries a *position* and the *schema's* expectations — never a byte of
    /// the file's content.
    ///
    /// This variant deliberately has no `#[source]` and keeps no rendered
    /// parser text. It used to hold both, on the reasoning that `Display`
    /// suppressed them and only callers who opted into walking the chain would
    /// see them. That reasoning was wrong: `main` returns `anyhow::Result`, and
    /// `anyhow`'s `Debug` renders the whole `Caused by:` chain when `main`
    /// returns `Err`. A password mis-pasted into an enum-typed field printed
    /// verbatim to the terminal on boot:
    ///
    /// ```text
    /// Caused by:
    ///     unknown variant `hunter2`, expected one of postgres, mysql, ...
    /// ```
    ///
    /// So the chain is severed here instead. Attaching a `#[source]` to this
    /// variant re-opens it — the leak is one attribute away, which is why there
    /// is a test for it.
    ///
    /// [`Self::expected`] survives because it is derived from our own schema
    /// (variant and field names), never from user input — see
    /// [`schema_expectation`].
    #[error("{path}{location}: invalid configuration{expected}")]
    Parse {
        path: PathBuf,
        /// `:line:column` when the parser knows it, empty otherwise.
        location: String,
        /// `" (expected one of …)"` when the parser named the schema's
        /// alternatives, empty otherwise. Safe to render: schema-derived.
        expected: String,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
    /// CLAUDE.md: "Never run as DB superuser. Per-DB read-only roles, full
    /// stop." Split out from `Invalid` so callers (structured loggers, tests,
    /// future admin surfaces) classify this outcome by variant rather than
    /// substring-matching a message that's free to evolve.
    #[error(
        "database `{db_name}` in server `{server_name}` connects as `{role}`, \
         the stock superuser for `{kind:?}`. The gateway must never hold a \
         superuser credential — create a per-database read-only role and use \
         that instead (see \
         https://developerz-ai.github.io/db-mcp-gateway/docs/initial-idea/credentials)"
    )]
    StockSuperuserRole {
        role: String,
        kind: ServerKind,
        db_name: String,
        server_name: String,
    },
    /// Blank/whitespace-only `host` on a `logging.stream[].kind: syslog` sink.
    /// Split out from `Invalid` so callers (structured loggers, tests, future
    /// admin surfaces) classify this outcome by variant rather than
    /// substring-matching a message that's free to evolve. Same rationale as
    /// [`Self::StockSuperuserRole`]. The `index` names the sink position so an
    /// operator with several sinks can point at the offending one.
    #[error(
        "logging.stream[{index}] syslog `host` must be non-blank — a blank \
         host deserializes cleanly but fails DNS on every audit event inside \
         the detached delivery task, which drops silently"
    )]
    SyslogSinkBlankHost { index: usize },
    /// Port `0` on a `logging.stream[].kind: syslog` sink. Port 0 is the
    /// wildcard "any port" for socket binds, not a valid destination — a
    /// `send_to` targeting it fails at delivery time. Rejected at boot for the
    /// same operator-visibility reason as [`Self::SyslogSinkBlankHost`].
    #[error(
        "logging.stream[{index}] syslog `port` must be non-zero — port 0 is a \
         bind wildcard, not a valid destination, and every send would fail at \
         delivery time"
    )]
    SyslogSinkZeroPort { index: usize },
}

impl ConfigFileError {
    /// Build a `Parse` error with location information extracted up-front.
    /// Operators read `Display` first; making them dig through `source()`
    /// for line numbers is the polish #16 is fixing.
    pub(super) fn parse_from(path: PathBuf, source: serde_saphyr::Error) -> Self {
        let location = source
            .location()
            .map(|loc| format!(":{}:{}", loc.line(), loc.column()))
            .unwrap_or_default();
        // `source` is read for position and expectations, then dropped. Storing
        // it would put the file's own bytes back into the error — see the
        // `Parse` doc comment.
        let expected = schema_expectation(&source.to_string())
            .map(|list| format!(" ({list})"))
            .unwrap_or_default();
        ConfigFileError::Parse {
            path,
            location,
            expected,
        }
    }
}

/// Pull the schema-derived tail out of a parser message, discarding everything
/// before it.
///
/// serde puts the *input* token first and the *schema's* alternatives second —
/// ``unknown variant `hunter2`, expected one of postgres, mysql`` — so keeping
/// only the text from `expected one of` onward is safe by construction: past
/// that marker, every word comes from our own enum and struct definitions.
///
/// The safety therefore does not rest on redacting the token. It rests on never
/// copying the part of the string the token can appear in. A denylist would
/// have to keep pace with the parser's phrasing; this cannot silently start
/// leaking if that phrasing changes — it can only stop finding the marker and
/// return `None`.
fn schema_expectation(message: &str) -> Option<String> {
    const MARKER: &str = "expected one of ";
    let tail = &message[message.find(MARKER)?..];
    // serde-saphyr appends its own " at line N, column M"; ours is already in
    // `location`, so drop the duplicate.
    let list = tail.split(" at line ").next().unwrap_or(tail);
    Some(list.trim_end_matches([' ', ',']).to_string())
}
