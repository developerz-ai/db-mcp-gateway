//! The measured path: an MCP `tools/call` for `run_query` over HTTP.
//!
//! This drives the gateway exactly as an agent does — real binary, real
//! service-token auth, real synchronous audit write. Nothing here reaches into
//! the library to shortcut a layer, because a benchmark of a build we do not
//! ship is worth less than no benchmark.
//!
//! The path is **backend-aware**: the same `tools/call` envelope carries a
//! SQL string for a postgres target and a mongo command document for a mongo
//! target. The gateway dispatches on the *configured server's* kind, so the
//! harness only has to name the right `server`/`database` pair — the shape
//! carries the query text for whichever backend it belongs to.

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

    /// The MCP endpoint this client posts to. Used by the scaling phase's
    /// console output so a reader can tell which instance answered.
    pub fn mcp_url(&self) -> &str {
        &self.mcp_url
    }

    /// Issue one query and return its wall-clock latency in milliseconds.
    ///
    /// The clock covers request-send through response-parsed, which is what an
    /// agent actually waits for. It therefore includes JSON encode/decode on
    /// both ends — that cost is real and the direct baseline does not pay it,
    /// which is precisely the kind of thing the comparison should surface
    /// rather than subtract away.
    pub async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, GatewayError> {
        let body = run_query_envelope(&self.server, &self.database, shape, iteration);

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

/// The `tools/call` envelope for one measured request — the production
/// builder `GatewayClient::run` sends.
///
/// Extracted from `run` so the envelope test exercises this function rather
/// than re-typing the JSON: a test that assembled its own envelope would
/// keep passing if `run` drifted away from it (say, back to sending SQL for
/// every backend).
fn run_query_envelope(server: &str, database: &str, shape: Shape, iteration: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": iteration,
        "method": "tools/call",
        "params": {
            "name": "run_query",
            "arguments": {
                "server": server,
                "database": database,
                // One field carries both dialects: SQL for a postgres
                // target, a mongo command document for a mongo target.
                // The gateway's server kind decides which it parses.
                "sql": shape.query(iteration),
                "limit": shape.limit(),
            }
        }
    })
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
            // `truncated` must be explicitly `false`. A truncated envelope
            // carries a partial row set, and the direct baseline never
            // truncates — comparing the two would report gateway overhead
            // measured against a smaller response than the baseline paid for.
            payload.get("truncated").and_then(Value::as_bool) == Some(false)
                && payload
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
    fn truncated_envelope_with_rows_is_rejected() {
        // A gateway response with rows and `truncated: true` used to slip
        // through because the filter only checked for a non-empty `rows`.
        // Timing it would compare a partial result against the direct path's
        // complete result — the gateway would look artificially fast.
        let response = envelope(json!({"columns": ["id"], "rows": [[1]], "truncated": true}));
        assert!(matches!(
            validate_response(&response),
            Err(GatewayError::MalformedPayload)
        ));
    }

    #[test]
    fn envelope_missing_truncated_is_rejected() {
        // Defensive: the gateway always emits `truncated`, but if a future
        // change dropped it the harness must refuse to time the response
        // rather than silently treat "unknown" as complete.
        let response = envelope(json!({"columns": ["id"], "rows": [[1]]}));
        assert!(matches!(
            validate_response(&response),
            Err(GatewayError::MalformedPayload)
        ));
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

    /// The measured envelope must be the production builder's output: the
    /// MCP `tools/call` framing, `run_query`, and the shape's own query text
    /// and row cap in the arguments. For a mongo shape the query text is the
    /// command document — `shape.sql()` returns the empty string there, so
    /// this assertion fails if the builder ever sent SQL for both dialects.
    #[test]
    fn the_envelope_is_built_by_the_production_builder() {
        let shape = Shape::MongoPointFind;
        let body = run_query_envelope("target-mongo", "app", shape, 3);
        assert_eq!(body["jsonrpc"], json!("2.0"));
        assert_eq!(body["id"], json!(3));
        assert_eq!(body["method"], json!("tools/call"));
        assert_eq!(body["params"]["name"], json!("run_query"));
        let arguments = &body["params"]["arguments"];
        assert_eq!(arguments["server"], json!("target-mongo"));
        assert_eq!(arguments["database"], json!("app"));
        assert_eq!(
            arguments["sql"],
            json!(shape.command(3)),
            "a mongo shape must carry the command document, not SQL"
        );
        assert_eq!(arguments["limit"], json!(shape.limit()));

        // And the postgres dialect stays SQL.
        let point = Shape::PointLookup;
        let body = run_query_envelope("target", "app", point, 0);
        assert_eq!(
            body["params"]["arguments"]["sql"],
            json!(point.sql(0)),
            "a postgres shape must carry SQL"
        );
    }

    /// Several gateway base URLs must produce several distinct clients —
    /// the scaling phase needs one client per instance.
    #[test]
    fn each_base_url_yields_its_own_endpoint() {
        let a = GatewayClient::new(
            "http://127.0.0.1:9001/",
            "/mcp",
            "t".into(),
            "target".into(),
            "app".into(),
        )
        .expect("client constructs");
        let b = GatewayClient::new(
            "http://127.0.0.1:9002",
            "/mcp",
            "t".into(),
            "target".into(),
            "app".into(),
        )
        .expect("client constructs");
        assert_eq!(a.mcp_url(), "http://127.0.0.1:9001/mcp");
        assert_eq!(b.mcp_url(), "http://127.0.0.1:9002/mcp");
        assert_ne!(a.mcp_url(), b.mcp_url());
    }
}
