//! `login`: the gateway's own OAuth 2.1 flow, as a native app runs it
//! (RFC 8252): register a loopback redirect (`/register`), send the operator's
//! browser to `/authorize` with a PKCE S256 challenge, catch the code on
//! `127.0.0.1`, redeem it at `/token`. The session token lands in a 0600 file.

use std::time::Duration;

use db_mcp_gateway::auth::pkce;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use uuid::Uuid;

use super::super::CliError;
use super::client::{ensure_success, http_client};
use super::session_file::StoredSession;

/// How long the operator has to finish signing in.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
/// A callback request line plus headers fits well inside this.
const MAX_CALLBACK_REQUEST: usize = 16 * 1024;
const CALLBACK_PATH: &str = "/callback";

pub async fn run(gateway: &str) -> Result<StoredSession, CliError> {
    let gateway = gateway.trim_end_matches('/');
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| CliError::io("bind a loopback port for the login callback", err))?;
    let port = listener
        .local_addr()
        .map_err(|err| CliError::io("read the loopback port", err))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
    let http = http_client(None)?;
    let client_id = register(&http, gateway, &redirect_uri).await?;
    let (verifier, challenge) = pkce::generate();
    let state = Uuid::new_v4().simple().to_string();
    let authorize = authorize_url(gateway, &client_id, &redirect_uri, &challenge, &state)?;
    eprintln!("Open this URL in a browser and sign in:\n\n  {authorize}\n");
    eprintln!("Waiting for the sign-in to finish (up to {LOGIN_TIMEOUT:?})...");
    let code = tokio::time::timeout(LOGIN_TIMEOUT, receive_code(&listener, &state))
        .await
        .map_err(|_| CliError::Invalid("sign-in did not finish in time".to_string()))??;
    redeem(&http, gateway, &client_id, &redirect_uri, &code, &verifier).await
}

async fn register(
    http: &reqwest::Client,
    gateway: &str,
    redirect_uri: &str,
) -> Result<String, CliError> {
    let url = format!("{gateway}/register");
    let response = http
        .post(&url)
        .json(&json!({ "redirect_uris": [redirect_uri], "client_name": "db-mcp-gateway CLI" }))
        .send()
        .await
        .map_err(|err| CliError::unreachable(gateway, &err))?;
    let body: Value = ensure_success("register the CLI client", response)
        .await?
        .json()
        .await
        .map_err(|err| CliError::unreachable(gateway, &err))?;
    body["client_id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| CliError::Invalid("/register returned no client_id".to_string()))
}

fn authorize_url(
    gateway: &str,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> Result<Url, CliError> {
    Url::parse_with_params(
        &format!("{gateway}/authorize"),
        [
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", state),
        ],
    )
    .map_err(|_| CliError::Usage(format!("--url `{gateway}` is not a URL")))
}

/// Serve callbacks until one carries our `state`; anything else (a favicon
/// fetch, a stale tab) gets a 400 and the wait goes on.
async fn receive_code(listener: &TcpListener, state: &str) -> Result<String, CliError> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|err| CliError::io("accept the login callback", err))?;
        let Some(params) = read_callback(&mut stream).await else {
            respond(&mut stream, "400 Bad Request", "Not a login callback.").await;
            continue;
        };
        if params.get("state").map(String::as_str) != Some(state) {
            respond(&mut stream, "400 Bad Request", "Unknown login attempt.").await;
            continue;
        }
        if let Some(error) = params.get("error") {
            respond(&mut stream, "200 OK", "Sign-in failed; see the terminal.").await;
            // An OAuth error code is a fixed token from the spec, not user data.
            return Err(CliError::Invalid(format!("sign-in failed: {error}")));
        }
        let Some(code) = params.get("code") else {
            respond(&mut stream, "400 Bad Request", "No authorization code.").await;
            continue;
        };
        respond(&mut stream, "200 OK", "Signed in. You can close this tab.").await;
        return Ok(code.clone());
    }
}

/// The query of a `GET /callback?…` request, or `None` for anything else.
async fn read_callback(
    stream: &mut TcpStream,
) -> Option<std::collections::HashMap<String, String>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_CALLBACK_REQUEST {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let head = std::str::from_utf8(&buf).ok()?;
    let target = head.strip_prefix("GET ")?.split(' ').next()?;
    let url = Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    (url.path() == CALLBACK_PATH).then(|| url.query_pairs().into_owned().collect())
}

/// Best effort: the browser tab's message is cosmetic, the code is what counts.
async fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!("<!doctype html><title>db-mcp-gateway</title><p>{message}</p>");
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn redeem(
    http: &reqwest::Client,
    gateway: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<StoredSession, CliError> {
    let response = http
        .post(format!("{gateway}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|err| CliError::unreachable(gateway, &err))?;
    let body: Value = ensure_success("redeem the authorization code", response)
        .await?
        .json()
        .await
        .map_err(|err| CliError::unreachable(gateway, &err))?;
    let access_token = body["access_token"]
        .as_str()
        .ok_or_else(|| CliError::Invalid("/token returned no access_token".to_string()))?;
    let expires_at = body["expires_in"]
        .as_i64()
        .map(|secs| chrono::Utc::now().timestamp() + secs);
    Ok(StoredSession {
        url: gateway.to_string(),
        access_token: access_token.to_string(),
        refresh_token: body["refresh_token"].as_str().map(str::to_string),
        expires_at,
    })
}
