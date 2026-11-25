//! Driver error → [`ExecError`]. Same discipline as the pg and Mongo
//! adapters: the driver error is never rendered; only its kind and the
//! server's error code are logged.

use std::sync::atomic::Ordering;

use redis::{ErrorKind, RedisError, ServerErrorKind};

use super::super::adapter::ExecError;
use super::super::rejection::DbRejection;
use super::RedisAdapter;

/// Stand-in for the ACL username inside a server message. Redis names the
/// user unquoted (`User gateway_ro has no permissions …`).
const ROLE_PLACEHOLDER: &str = "<role>";

/// Whether the connection is still in step after `err`: a server error is a
/// complete reply, so the connection can serve the next caller. Anything
/// else (I/O, a protocol error) leaves it in an unknown state.
pub(super) fn connection_survives(err: &RedisError) -> bool {
    matches!(err.kind(), ErrorKind::Server(_) | ErrorKind::Extension)
}

/// Whether `err` says the connection itself is gone — closed by the server
/// or the network — rather than that a command failed on it.
pub(super) fn connection_lost(err: &RedisError) -> bool {
    !connection_survives(err)
        && (err.kind() == ErrorKind::Io || err.is_io_error() || err.is_connection_dropped())
}

impl RedisAdapter {
    /// A command's failure. A server error reply is passed to the agent as a
    /// [`DbRejection`] (code + message, ACL username redacted) — `NOPERM`
    /// maps to `permission_denied`, anything else to `syntax_error`.
    ///
    /// A reply about the server's state rather than the command is the
    /// exception: a cluster redirect (`MOVED` / `ASK` carry another node's
    /// address), a cluster or replica that cannot serve, a dataset still
    /// loading, a script holding the server busy. None of them is anything
    /// the agent can fix in its command. They are `unavailable`, text
    /// dropped.
    pub(super) fn classify_command(&self, err: RedisError) -> ExecError {
        if is_unavailable_reply(&err) {
            tracing::warn!(
                error_kind = "server_state",
                code = err.code().unwrap_or("ERR"),
                "target command failed"
            );
            return ExecError::Unavailable;
        }
        if connection_survives(&err) {
            let code = err.code().unwrap_or("ERR");
            tracing::warn!(error_kind = "server", code, "target command failed");
            let message = redact_role(err.detail().unwrap_or_default(), &self.role);
            return ExecError::Rejected(DbRejection::new(code, &message, &self.role));
        }
        self.classify_transport(err)
    }

    /// A failure to open a connection. Never becomes a [`DbRejection`]: a
    /// handshake error can name the user or the database.
    pub(super) fn classify_connect(&self, err: RedisError) -> ExecError {
        if err.kind() == ErrorKind::AuthenticationFailed {
            self.stale.store(true, Ordering::Relaxed);
            tracing::warn!(error_kind = "authentication", "target connect failed");
            return ExecError::Connection;
        }
        if connection_survives(&err) {
            // e.g. `SELECT` refused: misconfiguration, not the agent's input.
            let code = err.code().unwrap_or("ERR");
            tracing::warn!(error_kind = "server", code, "target connect failed");
            return ExecError::Connection;
        }
        // Unreachable or timed out: the target is down. Anything else — a
        // TLS certificate the client refused, a bad client config — is the
        // connection's setup failing, never the agent's command.
        let (kind, mapped) = if err.kind() == ErrorKind::Io || err.is_io_error() || err.is_timeout()
        {
            ("io", ExecError::Unavailable)
        } else {
            ("setup", ExecError::Connection)
        };
        tracing::warn!(error_kind = kind, "target connect failed");
        mapped
    }

    fn classify_transport(&self, err: RedisError) -> ExecError {
        let (kind, mapped) = match err.kind() {
            ErrorKind::AuthenticationFailed => {
                self.stale.store(true, Ordering::Relaxed);
                ("authentication", ExecError::Connection)
            }
            ErrorKind::Io => ("io", ExecError::Unavailable),
            ErrorKind::Parse | ErrorKind::UnexpectedReturnType => ("decode", ExecError::Decode),
            ErrorKind::InvalidClientConfig => ("config", ExecError::Connection),
            _ if err.is_io_error() || err.is_connection_dropped() || err.is_timeout() => {
                ("io", ExecError::Unavailable)
            }
            _ => ("other", ExecError::Sql),
        };
        tracing::warn!(error_kind = kind, "target command failed");
        mapped
    }
}

/// The server answered about its own state — where the data lives, whether
/// it can serve at all — not about the command.
fn is_unavailable_reply(err: &RedisError) -> bool {
    match err.kind() {
        ErrorKind::Server(kind) => matches!(
            kind,
            ServerErrorKind::Moved
                | ServerErrorKind::Ask
                | ServerErrorKind::TryAgain
                | ServerErrorKind::ClusterDown
                | ServerErrorKind::MasterDown
                | ServerErrorKind::BusyLoading
        ),
        // The driver has no kind for `BUSY` (a script or function running
        // past `busy-reply-threshold`).
        ErrorKind::Extension => err.code() == Some("BUSY"),
        _ => false,
    }
}

/// Replace every whole-word occurrence of `role` — bounded by characters an
/// ACL username in the config cannot contain — with [`ROLE_PLACEHOLDER`].
fn redact_role(message: &str, role: &str) -> String {
    if role.is_empty() {
        return message.to_string();
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(message.len());
    let mut copied = 0;
    for (at, _) in message.match_indices(role) {
        // Neighbours come from the whole message: a slice starting right
        // after the previous match would hide a word character before `at`.
        let before = message[..at].chars().next_back();
        let after = message[at + role.len()..].chars().next();
        if before.is_some_and(is_word) || after.is_some_and(is_word) {
            continue;
        }
        out.push_str(&message[copied..at]);
        out.push_str(ROLE_PLACEHOLDER);
        copied = at + role.len();
    }
    out.push_str(&message[copied..]);
    out
}

#[cfg(test)]
#[path = "redact_proptests.rs"]
mod redact_proptests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_the_acl_user_as_a_whole_word_only() {
        assert_eq!(
            redact_role(
                "User gateway_ro has no permissions to run the 'set' command",
                "gateway_ro"
            ),
            "User <role> has no permissions to run the 'set' command"
        );
        // A key or word that merely contains the name is left alone.
        assert_eq!(
            redact_role("key gateway_ro_x and gateway_ro.", "gateway_ro"),
            "key gateway_ro_x and <role>."
        );
        assert_eq!(redact_role("no role here", "ro"), "no role here");
        // Back-to-back copies are one longer word, not two whole words.
        assert_eq!(redact_role("roro ro", "ro"), "roro <role>");
    }

    fn server_error(reply: &[u8]) -> RedisError {
        redis::parse_redis_value(reply)
            .and_then(|v| v.extract_error())
            .expect_err("a server error")
    }

    async fn adapter() -> RedisAdapter {
        use crate::config::{Database, Password, Server, ServerKind, Tls};
        let database = Database {
            name: "0".into(),
            role: "gateway_ro".into(),
            password: Password::Literal("pw".into()),
            description: String::new(),
            auth_database: None,
            connect_name: None,
            pool: None,
            write_role: None,
            write_password: None,
        };
        let server = Server {
            name: "cache".into(),
            kind: ServerKind::Redis,
            description: String::new(),
            host: "cache.internal".into(),
            port: 6379,
            tls: Tls::Insecure,
            tls_ca_file: None,
            pool: None,
            databases: vec![],
        };
        // Lazy: nothing connects.
        RedisAdapter::open(&server, &database, Default::default())
            .await
            .expect("client builds")
    }

    /// A redirect names another node's address; the agent gets neither the
    /// address nor a "fix your command" code. A server that cannot serve
    /// right now is likewise not the command's fault.
    #[tokio::test]
    async fn server_state_replies_are_unavailable_without_their_text() {
        let adapter = adapter().await;
        for reply in [
            &b"-MOVED 3999 10.0.0.5:6381\r\n"[..],
            b"-ASK 3999 10.0.0.5:6381\r\n",
            b"-TRYAGAIN Multiple keys request during rehashing of slot\r\n",
            b"-CLUSTERDOWN The cluster is down\r\n",
            b"-MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'.\r\n",
            b"-LOADING Redis is loading the dataset in memory\r\n",
            b"-BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSCRIPT.\r\n",
        ] {
            let mapped = adapter.classify_command(server_error(reply));
            assert!(matches!(mapped, ExecError::Unavailable), "{mapped:?}");
        }
        let wrong_type = adapter.classify_command(server_error(b"-WRONGTYPE not a list\r\n"));
        assert!(
            matches!(wrong_type, ExecError::Rejected(_)),
            "{wrong_type:?}"
        );
        // Another extension code stays the command's rejection.
        let busy_key = adapter.classify_command(server_error(
            b"-BUSYKEY Target key name already exists.\r\n",
        ));
        assert!(matches!(busy_key, ExecError::Rejected(_)), "{busy_key:?}");
    }

    #[test]
    fn only_server_replies_keep_the_connection() {
        let server = redis::parse_redis_value(b"-NOPERM nope\r\n")
            .and_then(|v| v.extract_error())
            .expect_err("a server error");
        assert!(connection_survives(&server));
        let io = RedisError::from(std::io::Error::other("reset"));
        assert!(!connection_survives(&io));
    }
}
