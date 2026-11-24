//! Harness for tests that boot the real `db-mcp-gateway` binary: what only the
//! process proves — boot order, the background pools, the env knobs `main`
//! reads, and the JSON log lines on stdout.
//!
//! The child gets a cleared environment plus exactly the variables set here,
//! so a developer's shell (`RUST_LOG`, a stray `TLS_CERT_PATH`) cannot change
//! what a test sees.

// audit-guard: exempt — the harness only builds requests; every boot_*.rs test that calls a tool asserts its audit row.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::time::{Instant, sleep};

use crate::common::env::state_db_url;

const BOOT_DEADLINE: Duration = Duration::from_secs(60);
const LISTENING: &str = "db-mcp-gateway listening";

/// A running gateway process; killed on drop.
pub struct BinaryGateway {
    child: Child,
    pub base_url: String,
    output: Arc<Mutex<Vec<String>>>,
    _config: NamedTempFile,
}

/// A port nothing listens on right now.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("bind an ephemeral port")
        .port()
}

impl BinaryGateway {
    /// Start the binary with `yaml` as its config. `env` overrides the
    /// defaults (plain HTTP on loopback, a loopback IdP that is never called,
    /// the dev-stack state DB).
    pub fn spawn(yaml: &str, env: &[(&str, &str)]) -> Self {
        let config = NamedTempFile::new().expect("temp config");
        std::fs::write(config.path(), yaml).expect("write config");
        let port = free_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_db-mcp-gateway"));
        command
            .arg("--config")
            .arg(config.path())
            .env_clear()
            .env("RUST_LOG", "info")
            .env("TLS_DISABLED", "true")
            .env("OIDC_ISSUER", "http://127.0.0.1:9")
            .env("OIDC_CLIENT_ID", "boot-binary-test")
            .env("ALLOW_INSECURE_SIGNING_KEY", "true")
            .env("GATEWAY_BIND", format!("127.0.0.1:{port}"))
            .env("METRICS_BIND", format!("127.0.0.1:{}", free_port()))
            .env("STATE_DB_URL", state_db_url())
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn the gateway binary");
        let output = Arc::new(Mutex::new(Vec::new()));
        collect(child.stdout.take(), output.clone());
        collect(child.stderr.take(), output.clone());
        Self {
            child,
            base_url: format!("http://127.0.0.1:{port}"),
            output,
            _config: config,
        }
    }

    /// Every stdout/stderr line so far.
    pub fn lines(&self) -> Vec<String> {
        self.output.lock().expect("output lock").clone()
    }

    /// The stdout lines that are JSON log records.
    pub fn records(&self) -> Vec<Value> {
        self.lines()
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// The first JSON log record matching `wanted`, polled until `within`:
    /// the process logs through a non-blocking writer and a reader thread,
    /// so a line can trail the HTTP response that caused it.
    pub async fn await_record(
        &self,
        within: Duration,
        wanted: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(line) = self.records().into_iter().find(|line| wanted(line)) {
                return Some(line);
            }
            if Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait until the listener is up; panics with the output if the process
    /// exits or the deadline passes first.
    pub async fn wait_listening(&mut self) {
        let deadline = Instant::now() + BOOT_DEADLINE;
        while !self.lines().iter().any(|line| line.contains(LISTENING)) {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                panic!(
                    "gateway exited ({status}) before listening:\n{:#?}",
                    self.lines()
                );
            }
            assert!(
                Instant::now() < deadline,
                "gateway not listening after {BOOT_DEADLINE:?}:\n{:#?}",
                self.lines()
            );
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait for the process to exit on its own within `within`.
    pub async fn wait_exit(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                // Let the reader threads take the last lines.
                sleep(Duration::from_millis(200)).await;
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "gateway still running after {within:?}:\n{:#?}",
                self.lines()
            );
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// POST a `tools/call` for `tool` with `token`, plus `headers`. Returns
    /// the HTTP status and the body (`Null` when it is not JSON).
    pub async fn call_tool(
        &self,
        token: &str,
        tool: &str,
        arguments: Value,
        headers: &[(&str, &str)],
    ) -> (u16, Value) {
        let mut request = reqwest::Client::new()
            .post(format!("{}/mcp", self.base_url))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2025-06-18")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments },
            }));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("gateway answers");
        let status = response.status().as_u16();
        let body = response.json().await.unwrap_or(Value::Null);
        (status, body)
    }
}

impl Drop for BinaryGateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: Option<impl Read + Send + 'static>, into: Arc<Mutex<Vec<String>>>) {
    let Some(stream) = stream else { return };
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { return };
            into.lock().expect("output lock").push(line);
        }
    });
}

/// A config with no servers and one service account `name` holding `token`,
/// for tests that only need an authenticated `list_servers`.
pub fn service_only_yaml(name: &str, token: &str) -> String {
    format!(
        "servers: []
permissions:
  - group: svc-{name}
    grants: []
service_accounts:
  - name: {name}
    group: svc-{name}
    token: {token}
"
    )
}
