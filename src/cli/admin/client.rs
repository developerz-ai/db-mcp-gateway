//! A bearer-authenticated client for `/admin/v1/*`. Every call it makes is a
//! normal admin API request, audited by the gateway exactly as one from any
//! other client.

use std::time::Duration;

use reqwest::{Method, RequestBuilder, Response};
use serde_json::Value;
use url::{Host, Url};

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
            base: gateway_url(base)?.to_string(),
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

/// `raw` without a trailing `/`, refused unless it is `https://` or
/// `http://` to a loopback host: the CLI sends a bearer, which plain HTTP
/// would hand to anyone on the path.
pub fn gateway_url(raw: &str) -> Result<&str, CliError> {
    let trimmed = raw.trim_end_matches('/');
    let refused = || {
        CliError::Usage(format!(
            "--url `{trimmed}` must be https://, or http:// to 127.0.0.1, [::1] or localhost"
        ))
    };
    let url = Url::parse(trimmed).map_err(|_| refused())?;
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(trimmed),
        "http" if loopback => Ok(trimmed),
        _ => Err(refused()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_travels_only_over_https_or_loopback() {
        for ok in [
            "https://gw.example.com",
            "https://gw.example.com/",
            "http://127.0.0.1:8080",
            "http://[::1]:8080/",
            "http://localhost:8080",
        ] {
            assert_eq!(
                gateway_url(ok).unwrap(),
                ok.trim_end_matches('/'),
                "{ok} is allowed"
            );
        }
        for refused in [
            "http://gw.example.com",
            "http://10.0.0.5:8080",
            "http://localhost.evil.example",
            "ftp://gw.example.com",
            "gw.example.com",
        ] {
            assert!(
                matches!(gateway_url(refused), Err(CliError::Usage(_))),
                "{refused} is refused"
            );
        }
    }
}
