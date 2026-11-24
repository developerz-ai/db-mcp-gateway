//! The file `login` stores the gateway session in: owner-only (0600) like an
//! SSH key, and refused on read when anyone else may read it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::CliError;

/// `Debug` is hand-rolled: the tokens are bearers.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredSession {
    /// The gateway this session belongs to; admin commands default to it.
    pub url: String,
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession")
            .field("url", &self.url)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// `$XDG_CONFIG_HOME/db-mcp-gateway/session.json`, else
/// `$HOME/.config/db-mcp-gateway/session.json`.
pub fn default_path() -> Result<PathBuf, CliError> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| {
            CliError::Usage("neither XDG_CONFIG_HOME nor HOME is set; pass --token-file".into())
        })?;
    Ok(base.join("db-mcp-gateway").join("session.json"))
}

/// Written to a fresh owner-only file beside `path`, then renamed over it: a
/// reader that already holds the old file open never sees the new bearer.
pub fn save(path: &Path, session: &StoredSession) -> Result<(), CliError> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir).map_err(|err| CliError::io(describe("create", dir), err))?;
    let body = serde_json::to_vec_pretty(session)
        .map_err(|err| CliError::io("encode the session", std::io::Error::other(err)))?;
    let temp = dir.join(format!(".session.{}.tmp", Uuid::new_v4().simple()));
    let written = write_new_private(&temp, &body).and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        // Best effort: the temp file holds the bearer, but is owner-only.
        let _ = fs::remove_file(&temp);
    }
    written.map_err(|err| CliError::io(describe("write", path), err))
}

/// `create_new` with mode 0600: never an existing file, never wider bits.
pub fn write_new_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

/// The permission check and the read use one handle, so a path swapped
/// between them cannot slip an unchecked file in.
pub fn load(path: &Path) -> Result<StoredSession, CliError> {
    let mut file = File::open(path).map_err(|err| {
        CliError::io(
            format!("read {} (run `db-mcp-gateway login`)", path.display()),
            err,
        )
    })?;
    let metadata = file
        .metadata()
        .map_err(|err| CliError::io(describe("read", path), err))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliError::Invalid(format!(
            "{} is readable by other users; run `chmod 600 {}` or log in again",
            path.display(),
            path.display()
        )));
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|err| CliError::io(describe("read", path), err))?;
    serde_json::from_slice(&raw).map_err(|_| {
        CliError::Invalid(format!(
            "{} is not a session file; run `db-mcp-gateway login`",
            path.display()
        ))
    })
}

fn describe(verb: &str, path: &Path) -> String {
    format!("{verb} {}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> StoredSession {
        StoredSession {
            url: "http://127.0.0.1:1".into(),
            access_token: "bearer-value".into(),
            refresh_token: None,
            expires_at: Some(1),
        }
    }

    #[test]
    fn saved_file_is_owner_only_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/session.json");
        save(&path, &session()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load(&path).unwrap().access_token, "bearer-value");
    }

    #[test]
    fn save_tightens_an_existing_file_and_load_refuses_a_shared_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&path), Err(CliError::Invalid(_))));
        save(&path, &session()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn save_replaces_the_file_so_an_open_reader_keeps_the_old_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut reader = File::open(&path).unwrap();
        save(&path, &session()).unwrap();
        let mut seen = String::new();
        reader.read_to_string(&mut seen).unwrap();
        assert_eq!(seen, "old");
        assert_eq!(load(&path).unwrap().access_token, "bearer-value");
        let leftovers = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "no temp file left behind");
    }

    #[test]
    fn debug_never_prints_a_token() {
        let rendered = format!("{:?}", session());
        assert!(!rendered.contains("bearer-value"), "{rendered}");
    }
}
