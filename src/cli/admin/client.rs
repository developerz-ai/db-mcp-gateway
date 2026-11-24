//! A bearer-authenticated client for `/admin/v1/*`. Every call it makes is a
//! normal admin API request, audited by the gateway exactly as one from any
//! other client.

use std::time::Duration;

use reqwest::{Method, RequestBuilder, Response};
use serde_json::Value;

use super::super::CliError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct AdminClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl AdminClient {
    pub fn new(base: &str, token: String) -> Result<Self, CliError> {
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            http: http_client(None)?,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }

    /// Send; a non-2xx answer becomes [`CliError::Refused`].
    pub async fn send(&self, what: &str, request: RequestBuilder) -> Result<Response, CliError> {
        let response = request
            .send()
            .await
            .map_err(|err| CliError::unreachable(&self.base, &err))?;
        ensure_success(what, response).await
    }

    pub async fn json(&self, what: &str, request: RequestBuilder) -> Result<Value, CliError> {
        self.send(what, request)
            .await?
            .json()
            .await
            .map_err(|err| CliError::unreachable(&self.base, &err))
    }
}

/// `None` → the default request timeout; streaming reads pass their own.
pub fn http_client(timeout: Option<Duration>) -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .timeout(timeout.unwrap_or(REQUEST_TIMEOUT))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| CliError::unreachable("the HTTP client", &err))
}

/// Admin bodies are `{"error": {"code", "message"}}`; OAuth bodies are
/// `{"error", "error_description"}`. Both are the gateway's own
/// credential-free text.
pub async fn ensure_success(what: &str, response: Response) -> Result<Response, CliError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body: Value = response.json().await.unwrap_or(Value::Null);
    let (code, message) = match &body["error"] {
        Value::Object(error) => (error.get("code"), error.get("message")),
        code @ Value::String(_) => (Some(code), body.get("error_description")),
        _ => (None, None),
    };
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .unwrap_or("(no detail)")
            .to_string()
    };
    Err(CliError::Refused {
        what: what.to_string(),
        status,
        code: text(code),
        message: text(message),
    })
}
