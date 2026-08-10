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
#[derive(Clone)]
pub struct GatewayClient {
    http: reqwest::Client,
    mcp_url: String,
    bearer: String,
    server: String,
    database: String,
}

// Hand-written so the service token can never reach a log line. Deriving
// `Debug` here would print `bearer` verbatim, breaking the credential
// non-negotiable in CLAUDE.md.
impl std::fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayClient")
            .field("mcp_url", &self.mcp_url)
            .field("server", &self.server)
            .field("database", &self.database)
            .field("bearer", &"<redacted>")
            .finish()
    }
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

        validate_response(&response)?;

        Ok(elapsed)
    }
}

/// Reject any envelope the benchmark cannot legitimately time.
///
/// Split out so it can be exercised without a live gateway — this is pure
/// JSON handling. Two failure modes:
///
/// - A JSON-RPC `error` object came back. We surface only the client-facing
///   `code`/`message`, never the raw body, which could echo a query or
///   connection detail into a log.
/// - The success envelope carries no rows. `{"rows":[]}` and columns-only
///   payloads are silent no-ops; timing them is the classic way to publish an
///   impossibly good number. The direct path already rejects the empty result,
///   so this guard keeps the two paths symmetric.
fn validate_response(response: &Value) -> Result<(), GatewayError> {
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

    response
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(|payload| {
            payload
                .get("rows")
                .and_then(Value::as_array)
                .is_some_and(|rows| !rows.is_empty())
        })
        .ok_or(GatewayError::MalformedPayload)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Wrap a `run_query` result payload in the MCP `tools/call` envelope the
    /// gateway actually emits: the payload is serialized into `content[0].text`.
    fn envelope(payload: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": payload.to_string()}
                ]
            }
        })
    }

    #[test]
    fn rpc_error_envelope_surfaces_only_client_facing_fields() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "forbidden"}
        });
        match validate_response(&response) {
            Err(GatewayError::Rpc { code, message }) => {
                assert!(code.contains("32000"), "code={code}");
                assert_eq!(message, "forbidden");
            }
            other => panic!("expected Rpc error, got {other:?}"),
        }
    }

    #[test]
    fn empty_rows_envelope_is_rejected_as_a_no_op() {
        let response = envelope(json!({"columns": ["id"], "rows": [], "truncated": false}));
        assert!(matches!(
            validate_response(&response),
            Err(GatewayError::MalformedPayload)
        ));
    }

    #[test]
    fn columns_only_envelope_is_rejected() {
        // Symmetric with the direct path, which also rejects an empty result.
        let response = envelope(json!({"columns": ["id"]}));
        assert!(matches!(
            validate_response(&response),
            Err(GatewayError::MalformedPayload)
        ));
    }

    #[test]
    fn populated_envelope_is_accepted() {
        let response = envelope(json!({"columns": ["id"], "rows": [[1]], "truncated": false}));
        validate_response(&response).expect("row present");
    }

    #[test]
    fn debug_output_never_contains_the_bearer_token() {
        let client = GatewayClient::new(
            "http://127.0.0.1:8899",
            "/mcp",
            "dbmcp_svc_secret_token".into(),
            "target".into(),
            "app".into(),
        )
        .expect("client constructs");
        let dumped = format!("{client:?}");
        assert!(
            !dumped.contains("secret_token"),
            "Debug leaked the service token: {dumped}"
        );
        assert!(dumped.contains("<redacted>"));
    }
}
