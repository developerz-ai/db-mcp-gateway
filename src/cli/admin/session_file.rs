//! The file `login` stores the gateway session in: owner-only (0600) like an
//! SSH key, and refused on read when anyone else may read it.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

pub fn save(path: &Path, session: &StoredSession) -> Result<(), CliError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|err| CliError::io(describe("create", dir), err))?;
    }
    let body = serde_json::to_vec_pretty(session)
        .map_err(|err| CliError::io("encode the session", std::io::Error::other(err)))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| CliError::io(describe("write", path), err))?;
    // `mode` applies only when the file is created; an older file keeps its
    // bits until this.
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(&body))
        .map_err(|err| CliError::io(describe("write", path), err))
}

pub fn load(path: &Path) -> Result<StoredSession, CliError> {
    let metadata = fs::metadata(path).map_err(|err| {
        CliError::io(
            format!("read {} (run `db-mcp-gateway login`)", path.display()),
            err,
        )
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliError::Invalid(format!(
            "{} is readable by other users; run `chmod 600 {}` or log in again",
            path.display(),
            path.display()
        )));
    }
    let raw = fs::read(path).map_err(|err| CliError::io(describe("read", path), err))?;
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
    fn debug_never_prints_a_token() {
        let rendered = format!("{:?}", session());
        assert!(!rendered.contains("bearer-value"), "{rendered}");
    }
}
