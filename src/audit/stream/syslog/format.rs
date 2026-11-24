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
    let timestamp = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let pid = std::process::id();
    // `unwrap_or_default()` can't actually trigger for this struct (no
    // non-string map keys, no NaN floats) but keeps a serialization
    // regression from panicking the fire-and-forget path — same reasoning
    // as `send_stdout`'s `groups` encoding.
    let body = serde_json::to_string(row).unwrap_or_default();
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // HOSTNAME and STRUCTURED-DATA are RFC 5424 NILVALUE ("-") — the
    // gateway doesn't track its own hostname, and the JSON body already
    // carries every field, so there's nothing structured data would add.
    format!("<{SYSLOG_PRI}>1 {timestamp} - {SYSLOG_APP_NAME} {pid} audit - {body}")
}

/// [`format_rfc5424`], cut to [`MAX_MESSAGE_BYTES`]. The `sql` field is cut
/// first, then `params`, so the body stays valid JSON; only if that cannot
/// make it fit is the message itself cut.
pub(in crate::audit::stream) fn message(row: &AuditRow) -> String {
    let message = format_rfc5424(row);
    let Some(excess) = message.len().checked_sub(MAX_MESSAGE_BYTES) else {
        return message;
    };
    // Budgeted by encoded size: escaping makes a quote two bytes and a
    // control character six, so a raw-length cut can leave the body too big.
    let mut shrunk = row.clone();
    if let Some(sql) = row.sql.as_deref()
        && let Some(keep) = json_len(sql).checked_sub(excess + TRUNCATION_MARKER.len())
    {
        shrunk.sql = Some(format!(
            "{}{TRUNCATION_MARKER}",
            prefix_within_json_len(sql, keep)
        ));
        let message = format_rfc5424(&shrunk);
        if message.len() <= MAX_MESSAGE_BYTES {
            return message;
        }
    }
    if let Some(params) = shrunk.params.as_ref().map(ToString::to_string) {
        // A cut array becomes a JSON string, as in `audit_calls.params`. Its
        // escapes make the string's encoding longer than the raw prefix, so
        // the cut shrinks by each overshoot until the body fits.
        let excess = format_rfc5424(&shrunk)
            .len()
            .saturating_sub(MAX_MESSAGE_BYTES);
        let mut keep = params
            .len()
            .saturating_sub(excess + TRUNCATION_MARKER.len());
        loop {
            shrunk.params = Some(serde_json::Value::String(format!(
                "{}{TRUNCATION_MARKER}",
                prefix_at_char_boundary(&params, keep)
            )));
            let message = format_rfc5424(&shrunk);
            match message.len().checked_sub(MAX_MESSAGE_BYTES) {
                None | Some(0) => return message,
                Some(_) if keep == 0 => break,
                Some(over) => keep = keep.saturating_sub(over),
            }
        }
    }
    let keep = MAX_MESSAGE_BYTES - TRUNCATION_MARKER.len();
    format!(
        "{}{TRUNCATION_MARKER}",
        prefix_at_char_boundary(&message, keep)
    )
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
