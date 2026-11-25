//! RFC 5424 message formatting, the size cap, and RFC 5425 octet framing.
//! Pure and synchronous so it is unit-testable without a socket.

use chrono::SecondsFormat;

use crate::audit::{AuditRow, prefix_at_char_boundary};

/// RFC 5424 PRI: `facility * 8 + severity`. `local0` (16) is the
/// conventional facility for application-generated audit/security events;
/// `informational` (6) matches "audit row streamed", not an error.
const SYSLOG_PRI: u8 = 16 * 8 + 6;
const SYSLOG_APP_NAME: &str = "db-mcp-gateway";

/// Largest message sent, on every transport. rsyslog's default
/// `maxMessageSize` is 8 KiB for UDP and TCP alike, and a 100 KB statement
/// exceeds the UDP payload limit outright, so a row that would not fit is cut
/// to fit rather than dropped.
pub(in crate::audit::stream) const MAX_MESSAGE_BYTES: usize = 8192;
/// Appended wherever a cut happened, so a receiver never mistakes a cut
/// statement for the whole one.
pub(in crate::audit::stream) const TRUNCATION_MARKER: &str = "...[truncated]";

/// Format one audit row as an RFC 5424 syslog message, MSG body = the row
/// as JSON (same data the durable `audit_calls` row holds — see
/// [`AuditRow`]'s `Serialize` doc).
pub(in crate::audit::stream) fn format_rfc5424(row: &AuditRow) -> String {
    // `unwrap_or_default()` can't actually trigger for this struct (no
    // non-string map keys, no NaN floats) but keeps a serialization
    // regression from panicking the fire-and-forget path — same reasoning
    // as `send_stdout`'s `groups` encoding.
    let body = serde_json::to_string(row).unwrap_or_default();
    envelope(&body)
}

fn envelope(body: &str) -> String {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let pid = std::process::id();
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // HOSTNAME and STRUCTURED-DATA are RFC 5424 NILVALUE ("-") — the
    // gateway doesn't track its own hostname, and the JSON body already
    // carries every field, so there's nothing structured data would add.
    format!("<{SYSLOG_PRI}>1 {timestamp} - {SYSLOG_APP_NAME} {pid} audit - {body}")
}

/// Bytes of JSON a cut field keeps while another field can still absorb the
/// excess, so one long field never costs the row the rest of its text.
const CUT_FLOOR: usize = 512;

/// Bytes of `error_message` the identity-only message keeps.
const IDENTITY_ERROR_BYTES: usize = 512;

/// [`format_rfc5424`], cut to [`MAX_MESSAGE_BYTES`]. Free text is cut field by
/// field in [`CUT_ORDER`] until the message fits: first down to [`CUT_FLOOR`]
/// each, then, when the row's other fields leave no room for that, to the
/// marker alone. Every cut ends in [`TRUNCATION_MARKER`] and the body stays
/// valid JSON throughout; a row that still does not fit is sent as its
/// identity.
pub(in crate::audit::stream) fn message(row: &AuditRow) -> String {
    let mut shrunk = row.clone();
    let mut message = format_rfc5424(&shrunk);
    for floor in [CUT_FLOOR, 0] {
        for field in CUT_ORDER {
            let Some(excess) = over_cap(&message) else {
                return message;
            };
            if field.cut(row, &mut shrunk, excess, floor) {
                message = format_rfc5424(&shrunk);
            }
        }
    }
    match over_cap(&message) {
        None => message,
        Some(_) => identity_only(row),
    }
}

/// How far `message` is past the cap; `None` when it fits.
fn over_cap(message: &str) -> Option<usize> {
    message
        .len()
        .checked_sub(MAX_MESSAGE_BYTES)
        .filter(|excess| *excess > 0)
}

/// A field [`message`] may cut.
#[derive(Debug, Clone, Copy)]
enum CutField {
    Sql,
    Params,
    AgentClient,
    UpstreamRunId,
    UpstreamActor,
    Reason,
    ErrorMessage,
}

/// The error message last: it is what the receiver cannot rebuild from the
/// rest of the row.
const CUT_ORDER: [CutField; 7] = [
    CutField::Sql,
    CutField::Params,
    CutField::AgentClient,
    CutField::UpstreamRunId,
    CutField::UpstreamActor,
    CutField::Reason,
    CutField::ErrorMessage,
];

impl CutField {
    /// Shorten this field of `shrunk` by `excess` bytes of JSON or down to
    /// `floor`, whichever leaves more. `row` holds the uncut text. `false`
    /// when there is nothing a cut would save.
    fn cut(self, row: &AuditRow, shrunk: &mut AuditRow, excess: usize, floor: usize) -> bool {
        let (whole, sent) = match self {
            Self::Params => return cut_params(row, shrunk, excess, floor),
            Self::Sql => (&row.sql, &mut shrunk.sql),
            Self::AgentClient => (&row.agent_client, &mut shrunk.agent_client),
            Self::UpstreamRunId => (&row.upstream_run_id, &mut shrunk.upstream_run_id),
            Self::UpstreamActor => (&row.upstream_actor, &mut shrunk.upstream_actor),
            Self::Reason => (&row.reason, &mut shrunk.reason),
            Self::ErrorMessage => (&row.error_message, &mut shrunk.error_message),
        };
        let (Some(whole), Some(now)) = (whole.as_deref(), sent.as_deref()) else {
            return false;
        };
        let Some(cut) = cut_text(whole, quoted_len(now), excess, floor) else {
            return false;
        };
        *sent = Some(cut);
        true
    }
}

/// A cut array becomes a JSON string, as in `audit_calls.params`.
fn cut_params(row: &AuditRow, shrunk: &mut AuditRow, excess: usize, floor: usize) -> bool {
    let (Some(whole), Some(now)) = (&row.params, &shrunk.params) else {
        return false;
    };
    let whole = match whole {
        // Already cut for `audit_calls`: the string is the text itself.
        serde_json::Value::String(text) => text.clone(),
        array => array.to_string(),
    };
    let Some(cut) = cut_text(&whole, now.to_string().len(), excess, floor) else {
        return false;
    };
    shrunk.params = Some(serde_json::Value::String(cut));
    true
}

/// A marked prefix of `whole` whose JSON string is `excess` bytes shorter
/// than the `now` bytes the field takes, or keeps `floor` bytes if that is
/// longer. `None` when it would not be shorter than `now`.
fn cut_text(whole: &str, now: usize, excess: usize, floor: usize) -> Option<String> {
    let marker = quoted_len(TRUNCATION_MARKER);
    let keep = now.saturating_sub(excess + marker).max(floor);
    let prefix = prefix_within_json_len(whole, keep);
    (prefix.len() < whole.len() && json_len(prefix) + marker < now)
        .then(|| format!("{prefix}{TRUNCATION_MARKER}"))
}

/// The last resort for a row whose fixed fields (groups, email) alone pass
/// the cap: enough to find the durable `audit_calls` row, and the start of
/// what went wrong, still one object.
fn identity_only(row: &AuditRow) -> String {
    let error_message = row.error_message.as_deref().map(|text| {
        let kept = prefix_within_json_len(text, IDENTITY_ERROR_BYTES);
        let marker = if kept.len() < text.len() {
            TRUNCATION_MARKER
        } else {
            ""
        };
        format!("{kept}{marker}")
    });
    let body = serde_json::json!({
        "id": row.id,
        "request_id": prefix_at_char_boundary(&row.request_id, 128),
        "tool": prefix_at_char_boundary(&row.tool, 128),
        "outcome": row.outcome,
        "error_message": error_message,
        "message_truncated": true,
    });
    envelope(&body.to_string())
}

/// The bytes `text` takes as a JSON string.
fn quoted_len(text: &str) -> usize {
    json_len(text) + 2
}

/// The bytes `text` takes inside a JSON string, quotes excluded.
fn json_len(text: &str) -> usize {
    text.chars().map(json_char_len).sum()
}

/// The longest prefix of `text` whose JSON encoding fits in `budget` bytes.
fn prefix_within_json_len(text: &str, budget: usize) -> &str {
    let mut used = 0;
    for (at, ch) in text.char_indices() {
        used += json_char_len(ch);
        if used > budget {
            return text.split_at(at).0;
        }
    }
    text
}

/// `serde_json`'s escaping: a short escape for quote, backslash and the
/// common control characters, `\u00XX` for the other control characters.
fn json_char_len(ch: char) -> usize {
    match ch {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        '\0'..='\u{1f}' => 6,
        other => other.len_utf8(),
    }
}

/// RFC 5425 §4.3 octet-counting frame (`MSG-LEN SP SYSLOG-MSG`), the framing
/// TCP and TLS receivers split a byte stream on. A message can carry a
/// newline (inside `sql`), so newline framing would split one row in two.
pub(in crate::audit::stream) fn octet_frame(message: &str) -> String {
    format!("{} {message}", message.len())
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod tests;
