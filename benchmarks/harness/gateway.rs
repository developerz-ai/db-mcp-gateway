//! The measured path: an MCP `tools/call` for `run_query` over HTTP.
//!
//! This drives the gateway exactly as an agent does — real binary, real
//! service-token auth, real synchronous audit write. Nothing here reaches into
//! the library to shortcut a layer, because a benchmark of a build we do not
//! ship is worth less than no benchmark.

use std::time::Instant;

use serde_json::{Value, json};

use crate::workload::Shape;

/// A `run_query` client bound to one gateway, one server, and one database.
#[derive(Debug, Clone)]
pub struct GatewayClient {
    http: reqwest::Client,
    mcp_url: String,
    bearer: String,
    server: String,
    database: String,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// A JSON-RPC error object came back. Carries only the gateway's own
    /// `code`/`message`, which are documented client-facing values — never the
    /// raw body, which could echo a query or a connection detail into a log.
    #[error("gateway returned error {code}: {message}")]
    Rpc { code: String, message: String },
    #[error("gateway response was not a run_query payload")]
    MalformedPayload,
}

impl GatewayClient {
    pub fn new(
        base_url: &str,
        mcp_path: &str,
        bearer: String,
        server: String,
        database: String,
    ) -> Result<Self, GatewayError> {
        let http = reqwest::Client::builder()
            // No pool cap: the driver's concurrency is the intended limit, and
            // a lower cap here would silently serialize requests and show up
            // as gateway latency that the gateway never spent.
            .pool_max_idle_per_host(usize::MAX)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(GatewayClient {
            http,
            mcp_url: format!("{}{}", base_url.trim_end_matches('/'), mcp_path),
            bearer,
            server,
            database,
        })
    }

    /// Issue one query and return its wall-clock latency in milliseconds.
    ///
    /// The clock covers request-send through response-parsed, which is what an
    /// agent actually waits for. It therefore includes JSON encode/decode on
    /// both ends — that cost is real and the direct baseline does not pay it,
    /// which is precisely the kind of thing the comparison should surface
    /// rather than subtract away.
    pub async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, GatewayError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": iteration,
            "method": "tools/call",
            "params": {
                "name": "run_query",
                "arguments": {
                    "server": self.server,
                    "database": self.database,
                    "sql": shape.sql(iteration),
                    "limit": shape.limit(),
                }
            }
        });

        let started = Instant::now();
        let response: Value = self
            .http
            .post(&self.mcp_url)
            .bearer_auth(&self.bearer)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;

        if let Some(err) = response.get("error") {
            return Err(GatewayError::Rpc {
                code: err
                    .get("code")
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }

        // Confirm we actually got rows rather than an empty success envelope.
        // A benchmark that silently measures no-ops is the classic way to
        // publish an impossibly good number.
        response
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .filter(|payload| payload.get("rows").is_some() || payload.get("columns").is_some())
            .ok_or(GatewayError::MalformedPayload)?;

        Ok(elapsed)
    }
}
