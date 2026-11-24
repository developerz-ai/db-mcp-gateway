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
    /// What diagnostics name: [`origin`] of `base`.
    shown: String,
    token: String,
    http: reqwest::Client,
}

impl AdminClient {
    pub fn new(base: &str, token: String) -> Result<Self, CliError> {
        let base = gateway_url(base)?;
        Ok(Self {
            base: base.to_string(),
            shown: origin(base),
            token,
            http: http_client(None, base)?,
        })
    }

    /// The gateway as diagnostics may name it.
    pub fn shown(&self) -> &str {
        &self.shown
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
            .map_err(|err| CliError::unreachable(&self.shown, &err))?;
        ensure_success(what, response).await
    }

    pub async fn json(&self, what: &str, request: RequestBuilder) -> Result<Value, CliError> {
        self.send(what, request)
            .await?
            .json()
            .await
            .map_err(|err| CliError::unreachable(&self.shown, &err))
    }
}

/// `raw` without a trailing `/`, refused unless it is `https://` or
/// `http://` to a loopback host (the CLI sends a bearer, which plain HTTP
/// would hand to anyone on the path), and refused if it carries userinfo, a
/// query or a fragment: a base URL has none, and a `user:password@` would
/// otherwise be stored and echoed. A refusal names [`origin`] at most.
pub fn gateway_url(raw: &str) -> Result<&str, CliError> {
    let trimmed = raw.trim_end_matches('/');
    let url = Url::parse(trimmed)
        .map_err(|_| CliError::Usage("--url is not an absolute URL".to_string()))?;
    let refused = |why: &str| {
        CliError::Usage(format!(
            "--url {} {why}",
            url.origin().ascii_serialization()
        ))
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused("must not carry user:password@"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(refused("must not carry a ?query or #fragment"));
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(trimmed),
        "http" if loopback => Ok(trimmed),
        _ => Err(refused(
            "must be https://, or http:// to 127.0.0.1, [::1] or localhost",
        )),
    }
}

/// `scheme://host[:port]` of `url` — never its userinfo, path, query or
/// fragment: all a diagnostic may say about a gateway URL.
pub fn origin(url: &str) -> String {
    Url::parse(url).map_or_else(
        |_| "(unparsable URL)".to_string(),
        |url| url.origin().ascii_serialization(),
    )
}

/// `None` → the default request timeout; streaming reads pass their own.
/// A plain-`http` gateway (loopback only, see [`gateway_url`]) is reached
/// directly: an `HTTP_PROXY` in the environment would otherwise carry the
/// bearer off the host in plaintext.
pub fn http_client(timeout: Option<Duration>, gateway: &str) -> Result<reqwest::Client, CliError> {
    let builder = reqwest::Client::builder()
        .timeout(timeout.unwrap_or(REQUEST_TIMEOUT))
        .redirect(reqwest::redirect::Policy::none());
    let builder = if gateway.starts_with("http://") {
        builder.no_proxy()
    } else {
        builder
    };
    builder
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

    #[test]
    fn userinfo_query_and_fragment_are_refused_without_echoing_the_url() {
        for refused in [
            "https://admin:hunter2@gw.example.com",
            "https://hunter2@gw.example.com",
            "http://admin:hunter2@localhost:8080",
            "https://gw.example.com/?token=hunter2",
            "https://gw.example.com/#hunter2",
            "https://gw.example.com/hunter2?",
            "ftp://admin:hunter2@gw.example.com",
            "not a url hunter2",
        ] {
            let Err(CliError::Usage(message)) = gateway_url(refused) else {
                panic!("{refused} is refused");
            };
            assert!(!message.contains("hunter2"), "{message}");
            assert!(!message.contains("admin"), "{message}");
        }
    }

    #[test]
    fn origin_drops_everything_but_scheme_host_and_port() {
        assert_eq!(
            origin("https://u:p@gw.example.com:8443/prefix?q=1#f"),
            "https://gw.example.com:8443"
        );
        assert_eq!(origin("http://localhost/x"), "http://localhost");
        assert_eq!(origin("::"), "(unparsable URL)");
    }
}
