//! The admin subcommands end to end: the real binary logs in through the
//! gateway's own OAuth flow (this test plays the browser), then drives the
//! audited admin API. Every write it makes must leave a `permissions_audit`
//! row attributed to the logged-in admin.

use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;

use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use reqwest::Url;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::cleanup::{
    delete_permissions_audit, delete_permissions_grant, delete_permissions_user,
};
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client};
use crate::common::idp::{MockUser, spawn_mock_idp};

const ADMIN_GROUP: &str = "cli-e2e-admins";
const YAML: &str = "servers:
  - name: prod
    kind: postgres
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
permissions: []
";

fn cli(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_db-mcp-gateway"));
    command.args(args).env_clear();
    command
}

/// `Command::output` blocks; the gateway under test shares this runtime.
async fn run(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(&args).output().expect("run the CLI")
    })
    .await
    .expect("CLI task")
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| part.to_string()).collect()
}

fn location(response: &reqwest::Response) -> String {
    response.headers()["location"].to_str().unwrap().to_string()
}

/// Read the authorize URL the CLI prints, then walk it as a browser would:
/// gateway → IdP → gateway callback → the CLI's loopback redirect. The
/// handle yields everything the CLI wrote to stderr once it exits.
async fn play_browser(child: &mut Child) -> std::thread::JoinHandle<String> {
    let stderr = child.stderr.take().expect("piped stderr");
    // Keep draining stderr after the URL: closing the pipe early would make
    // the CLI's next progress line fail with EPIPE and kill it.
    let (url_tx, url_rx) = std::sync::mpsc::channel();
    let drained = std::thread::spawn(move || {
        let mut all = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.trim().starts_with("http") {
                let _ = url_tx.send(line.trim().to_string());
            }
            all.push_str(&line);
            all.push('\n');
        }
        all
    });
    let authorize = tokio::task::spawn_blocking(move || {
        url_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the CLI prints the authorize URL")
    })
    .await
    .unwrap();
    let browser = no_redirect_client();
    let to_idp = browser.get(&authorize).send().await.unwrap();
    assert!(to_idp.status().is_redirection(), "{}", to_idp.status());
    let to_gateway = browser.get(location(&to_idp)).send().await.unwrap();
    let to_cli = browser.get(location(&to_gateway)).send().await.unwrap();
    let loopback = Url::parse(&location(&to_cli)).unwrap();
    assert_eq!(loopback.host_str(), Some("127.0.0.1"), "{loopback}");
    let done = browser.get(loopback).send().await.unwrap();
    assert!(done.status().is_success(), "{}", done.status());
    drained
}

async fn audit_row(pool: &PgPool, target: Uuid) -> (String, String) {
    sqlx::query_as(
        "SELECT action, actor_email FROM permissions_audit WHERE target_id = $1 \
         ORDER BY ts DESC, id DESC LIMIT 1",
    )
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("an audit row for the target")
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::parallel(world)]
async fn login_then_grants_and_session_revoke_are_audited() {
    let admin = MockUser {
        sub: format!("cli-admin-{}", Uuid::new_v4().simple()),
        email: "cli-admin@example.com".to_string(),
        groups: vec![ADMIN_GROUP.to_string()],
    };
    let target_sub = format!("cli-target-{}", Uuid::new_v4().simple());
    let pool = state_pool().await;
    let idp = spawn_mock_idp("test-client", "test-secret", admin.clone()).await;
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let gw = GatewayBuilder::new(YAML)
        .idp(&idp)
        .admin(ADMIN_GROUP, true)
        .repo(repo)
        .spawn(pool.clone())
        .await;
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("session.json");
    let token_arg = token_file.display().to_string();

    // login: loopback OAuth + PKCE, session stored owner-only.
    let mut child = cli(&["login", "--url", &gw.url, "--token-file", &token_arg])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = play_browser(&mut child).await;
    let login = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    let stderr = stderr.join().expect("stderr drained");
    assert!(login.status.success(), "{login:?}");
    let mode = std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let session: Value = serde_json::from_slice(&std::fs::read(&token_file).unwrap()).unwrap();
    let bearer = session["access_token"].as_str().unwrap().to_string();
    assert!(!bearer.is_empty());
    assert!(
        !String::from_utf8_lossy(&login.stdout).contains(&bearer),
        "login never prints the token to stdout"
    );
    assert!(
        stderr.contains("Open this URL") && !stderr.contains(&bearer),
        "login never prints the token to stderr: {stderr}"
    );

    // A subject to grant to (setup through the API directly).
    let user: Value = reqwest::Client::new()
        .post(format!("{}/admin/v1/users", gw.url))
        .bearer_auth(&bearer)
        .json(&json!({ "user_sub": target_sub, "user_email": "cli-target@example.com", "groups": [] }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    // grants apply: one POST per entry, each audited as the admin.
    let grants_file = dir.path().join("grants.json");
    let grants = json!([{ "user_id": user_id, "server": "prod", "db_name_wildcard": true, "action": "query_read" }]);
    std::fs::write(&grants_file, grants.to_string()).unwrap();
    let applied = run(args(&[
        "grants",
        "apply",
        "--token-file",
        &token_arg,
        &grants_file.display().to_string(),
    ]))
    .await;
    assert!(applied.status.success(), "{applied:?}");
    let stdout = String::from_utf8(applied.stdout).unwrap();
    let grant_id: Uuid = stdout
        .split_whitespace()
        .nth(2)
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| panic!("created grant id in {stdout:?}"));
    assert_eq!(
        audit_row(&pool, grant_id).await,
        ("create".to_string(), admin.email.clone())
    );

    // grants list reads it back.
    let listed = run(args(&[
        "grants",
        "list",
        "--token-file",
        &token_arg,
        "--user-id",
        &user_id.to_string(),
    ]))
    .await;
    assert!(listed.status.success(), "{listed:?}");
    let rows: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(rows[0]["id"], json!(grant_id));

    // sessions revoke by user_sub: resolved to the id, audited as an update.
    let revoked = run(args(&[
        "sessions",
        "revoke",
        "--token-file",
        &token_arg,
        &target_sub,
    ]))
    .await;
    assert!(revoked.status.success(), "{revoked:?}");
    assert_eq!(
        audit_row(&pool, user_id).await,
        ("update".to_string(), admin.email.clone())
    );

    // A refused call is exit 1 with the API's code, not a token.
    let missing = run(args(&[
        "sessions",
        "revoke",
        "--token-file",
        &token_arg,
        "nobody@nowhere",
    ]))
    .await;
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");

    delete_permissions_grant(&pool, grant_id).await;
    delete_permissions_audit(&pool, grant_id).await;
    delete_permissions_audit(&pool, user_id).await;
    delete_permissions_user(&pool, &target_sub).await;
    delete_permissions_user(&pool, &admin.sub).await;
}

/// `audit query` / `audit export` over `GET /admin/v1/audit/calls` (NDJSON).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::parallel(world)]
async fn audit_query_and_export_stream_ndjson() {
    let admin = MockUser {
        sub: format!("cli-audit-{}", Uuid::new_v4().simple()),
        email: "cli-audit@example.com".to_string(),
        groups: vec![ADMIN_GROUP.to_string()],
    };
    let pool = state_pool().await;
    let idp = spawn_mock_idp("test-client", "test-secret", admin.clone()).await;
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let gw = GatewayBuilder::new(YAML)
        .idp(&idp)
        .admin(ADMIN_GROUP, true)
        .repo(repo)
        .spawn(pool.clone())
        .await;
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("session.json");
    let token_arg = token_file.display().to_string();
    let mut child = cli(&["login", "--url", &gw.url, "--token-file", &token_arg])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _stderr = play_browser(&mut child).await;
    assert!(
        tokio::task::spawn_blocking(move || child.wait().unwrap())
            .await
            .unwrap()
            .success()
    );

    let user_param = format!("user={}", admin.sub);
    let queried = run(args(&[
        "audit",
        "query",
        "--token-file",
        &token_arg,
        "--param",
        "limit=5",
        "--param",
        &user_param,
    ]))
    .await;
    assert!(queried.status.success(), "{queried:?}");
    assert_own_audit_read(&String::from_utf8(queried.stdout).unwrap(), &admin.sub);
    let out = dir.path().join("audit.ndjson");
    let exported = run(args(&[
        "audit",
        "export",
        "--token-file",
        &token_arg,
        "--param",
        &user_param,
        "--out",
        &out.display().to_string(),
    ]))
    .await;
    assert!(exported.status.success(), "{exported:?}");
    assert_eq!(file_mode(&out), 0o600);
    assert_own_audit_read(&std::fs::read_to_string(&out).unwrap(), &admin.sub);

    delete_permissions_user(&pool, &admin.sub).await;
}

/// Every line is one JSON row, and the admin's own audited read is among
/// them: `admin.audit_calls` writes its row before streaming, so it is the
/// known seed.
fn assert_own_audit_read(ndjson: &str, sub: &str) {
    let rows: Vec<Value> = ndjson
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is one JSON row"))
        .collect();
    assert!(
        rows.iter()
            .any(|r| r["user_sub"] == sub && r["tool"] == "admin.audit_calls"),
        "{ndjson}"
    );
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}
