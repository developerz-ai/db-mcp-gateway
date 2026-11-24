use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;

/// A stand-in gateway for the transfer tests: answers one request with
/// `response` verbatim, then closes the connection.
async fn serve_once(response: &'static str) -> AdminClient {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let _ = stream.write_all(response.as_bytes()).await;
    });
    AdminClient::new(&base, "bearer".into()).unwrap()
}

#[tokio::test]
async fn a_cut_export_leaves_nothing_and_a_retry_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("audit.ndjson");
    // Promises 100 bytes, sends 11, hangs up.
    let cut = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{\"row\":1}\n\n").await;
    assert!(export(&cut, &[], &out).await.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    let whole = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n{\"row\":1}\n").await;
    export(&whole, &[], &out).await.unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "{\"row\":1}\n");
    let mode = std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&out).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn export_never_replaces_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("audit.ndjson");
    std::fs::write(&out, "keep").unwrap();
    let whole = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}").await;
    assert!(export(&whole, &[], &out).await.is_err());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep");
}

#[test]
fn a_uuid_shaped_subject_matches_by_subject() {
    let sub = "6f1c0a52-4f0e-4c55-9d0b-3f3a4a3f9a11";
    let row = json!({ "id": "0b6c2e6e-1d1f-4a63-8a43-6c3b0c8f2d10", "user_sub": sub });
    assert!(user_matches(&row, sub, None));
    assert!(user_matches(&row, sub, Some(UserField::Sub)));
    assert!(!user_matches(&row, sub, Some(UserField::Id)));
}

#[test]
fn a_value_naming_two_users_is_refused() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    assert_eq!(only_user(&[a], "x").unwrap(), a);
    assert!(matches!(only_user(&[], "x"), Err(CliError::Invalid(_))));
    let err = only_user(&[a, b], "x").unwrap_err();
    assert!(err.to_string().contains("--by"), "{err}");
}

#[test]
fn an_id_matches_in_any_case_and_a_subject_only_exactly() {
    let id = "0b6c2e6e-1d1f-4a63-8a43-6c3b0c8f2d10";
    let upper = id.to_uppercase();
    let owner = json!({ "id": id, "user_sub": "alice" });
    let other = json!({ "id": "6f1c0a52-4f0e-4c55-9d0b-3f3a4a3f9a11", "user_sub": upper });
    assert!(user_matches(&owner, &upper, Some(UserField::Id)));
    // Default lookup: both users match, so find_user refuses to guess.
    assert!(user_matches(&owner, &upper, None));
    assert!(user_matches(&other, &upper, None));
    assert!(!user_matches(&other, id, Some(UserField::Sub)));
}
