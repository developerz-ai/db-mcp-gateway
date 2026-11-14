//! Gateway consent for dynamically registered clients with a non-loopback
//! redirect (MCP security best practices, "Confused Deputy"). The IdP only ever
//! sees the gateway's static client, so its consent says nothing about who
//! receives the code; this page asks the signed-in user, after `/auth/callback`,
//! before any code is minted. See website/docs/initial-idea/04-auth-sso.md.

use axum::Form;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use url::Url;

use super::super::app_state::OAuthState;
use super::bridge_login::issue_code;
use super::helpers::{oauth_error, random_token, redirect_with_error};
use crate::auth::oauth::{AuthFacade, ClientName, GrantIdentity, OAuthBridge};

/// Where the consent form posts. Mounted by `transport::router`.
pub(in crate::transport) const CONSENT_PATH: &str = "/authorize/consent";

/// Stash the verified login and render the consent page. Nothing reaches the
/// client until a valid `POST` [`CONSENT_PATH`] approves it.
pub(super) async fn request_consent(
    auth: &AuthFacade,
    identity: GrantIdentity,
    bridge: OAuthBridge,
) -> Response {
    // The redirect was validated at /register and matched at /authorize, so
    // this only fails on a corrupted registry row: fail closed, no redirect.
    let Some(target) = RedirectTarget::parse(&bridge.client_redirect_uri) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        );
    };
    let consent_id = random_token();
    let csrf = random_token();
    let page = consent_page(&ConsentView {
        email: &identity.email,
        client_id: &bridge.client_id,
        client_name: bridge.client_name.as_ref().map(ClientName::as_str),
        redirect_uri: &bridge.client_redirect_uri,
        redirect_host: &target.host,
        consent_id: &consent_id,
        csrf: &csrf,
    });
    auth.flows
        .insert_consent(consent_id, csrf, identity, bridge)
        .await;
    with_page_headers(Html(page).into_response(), Some(&target.origin))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentForm {
    consent_id: String,
    csrf: String,
    decision: Decision,
}

/// `POST /authorize/consent` — the user's answer. Approve mints the code and
/// 303s it to the client; deny 303s `access_denied` (RFC 6749 §4.1.2.1). An
/// unknown, expired, reused or CSRF-mismatched submission releases nothing.
pub async fn consent(
    State(state): State<OAuthState>,
    form: Result<Form<ConsentForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return consent_rejected();
    };
    let Some(pending) = state.auth.flows.take_consent(&form.consent_id).await else {
        return consent_rejected();
    };
    if !pending.csrf_matches(&form.csrf) {
        tracing::warn!("consent submission with a mismatched CSRF token; flow discarded");
        return consent_rejected();
    }
    match form.decision {
        Decision::Approve => issue_code(&state.auth, pending.identity, &pending.bridge).await,
        Decision::Deny => redirect_with_error(&pending.bridge, "access_denied"),
    }
}

/// The redirect's host (shown to the user) and origin (allowed as a CSP
/// `form-action`, which browsers also apply to the post-submit redirect).
#[derive(Debug)]
struct RedirectTarget {
    host: String,
    origin: String,
}

impl RedirectTarget {
    fn parse(raw: &str) -> Option<Self> {
        let url = Url::parse(raw).ok()?;
        let host = url.host_str()?.to_owned();
        let origin = url.origin();
        origin.is_tuple().then(|| Self {
            host,
            origin: origin.ascii_serialization(),
        })
    }
}

#[derive(Debug)]
struct ConsentView<'a> {
    email: &'a str,
    client_id: &'a str,
    client_name: Option<&'a str>,
    redirect_uri: &'a str,
    redirect_host: &'a str,
    consent_id: &'a str,
    csrf: &'a str,
}

fn consent_page(view: &ConsentView<'_>) -> String {
    let email = escape_html(view.email);
    let client_id = escape_html(view.client_id);
    let client_name = view
        .client_name
        .map_or_else(|| "(no name)".to_owned(), escape_html);
    let redirect_uri = escape_html(view.redirect_uri);
    let host = escape_html(view.redirect_host);
    let consent_id = escape_html(view.consent_id);
    let csrf = escape_html(view.csrf);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Authorize application</title><style>\
body{{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;line-height:1.5}}\
.host{{font-size:1.4rem;font-weight:700;word-break:break-all}}\
.unverified{{color:#555;font-size:.9rem}}\
code{{word-break:break-all}}button{{font-size:1rem;padding:.5rem 1.25rem;margin-right:.75rem}}\
</style></head><body>\
<h1>Authorize database access?</h1>\
<p>You are signed in as <strong>{email}</strong>. An application is asking for \
access to the database gateway on your behalf. If you approve, your access will \
be sent to:</p>\
<p class=\"host\">{host}</p>\
<p>Full redirect: <code>{redirect_uri}</code><br>Client ID: <code>{client_id}</code> \
(self-registered; the gateway has not verified who operates it).</p>\
<p class=\"unverified\">Name the application gave itself (unverified, anyone can \
claim any name): <span class=\"client-name\">{client_name}</span></p>\
<p>Only approve if you started this sign-in and recognise <strong>{host}</strong>. \
Otherwise deny.</p>\
<form method=\"post\" action=\"{CONSENT_PATH}\">\
<input type=\"hidden\" name=\"consent_id\" value=\"{consent_id}\">\
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>\
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>\
</form></body></html>"
    )
}

/// Headers for the consent page: no framing (clickjacking a consent button is
/// the obvious attack), no scripts, no caching of the one-time tokens, and
/// forms may post only here — and redirect only to the client's origin.
fn with_page_headers(mut response: Response, redirect_origin: Option<&str>) -> Response {
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
         frame-ancestors 'none'; form-action 'self' {}",
        redirect_origin.unwrap_or_default()
    );
    let headers = response.headers_mut();
    if let Ok(csp) = HeaderValue::from_str(&csp) {
        headers.insert(CONTENT_SECURITY_POLICY, csp);
    }
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// A submission that cannot be tied to a live consent. Never redirects: with
/// no trusted flow there is no client redirect to send anything to.
fn consent_rejected() -> Response {
    let body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Authorization not completed</title></head><body>\
<h1>Authorization not completed</h1><p>This approval link expired or was already \
used. Start the connection again from your client.</p></body></html>";
    let response = (StatusCode::BAD_REQUEST, Html(body)).into_response();
    with_page_headers(response, None)
}

fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_neutralises_markup() {
        assert_eq!(
            escape_html("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
    }

    #[test]
    fn page_escapes_every_interpolated_value() {
        let page = consent_page(&ConsentView {
            email: "<script>e</script>",
            client_id: "\"><img>",
            client_name: Some("<script>alert(1)</script>"),
            redirect_uri: "https://evil.example/cb?<x>",
            redirect_host: "evil.example",
            consent_id: "id",
            csrf: "tok",
        });
        assert!(!page.contains("<script>e"));
        assert!(!page.contains("\"><img>"));
        assert!(!page.contains("?<x>"));
        assert!(!page.contains("<script>alert"));
        assert!(
            page.contains("class=\"client-name\">&lt;script&gt;alert(1)&lt;/script&gt;</span>")
        );
        assert!(page.contains("class=\"host\">evil.example<"));
    }

    #[test]
    fn missing_name_reads_as_no_name_and_host_stays_prominent() {
        let page = consent_page(&ConsentView {
            email: "u@example.com",
            client_id: "mcp-1",
            client_name: None,
            redirect_uri: "https://app.example/cb",
            redirect_host: "app.example",
            consent_id: "id",
            csrf: "tok",
        });
        assert!(page.contains("class=\"client-name\">(no name)</span>"));
        let host = page.find("class=\"host\"").expect("host line");
        let name = page.find("class=\"client-name\"").expect("name line");
        assert!(host < name, "redirect host renders before the claimed name");
    }

    #[test]
    fn page_headers_forbid_framing_and_caching() {
        let target = RedirectTarget::parse("https://app.example.com:8443/cb").expect("valid");
        assert_eq!(target.host, "app.example.com");
        let response = with_page_headers(Html("x").into_response(), Some(&target.origin));
        let header = |name: &str| response.headers()[name].to_str().unwrap().to_owned();
        assert_eq!(header("x-frame-options"), "DENY");
        assert_eq!(header("cache-control"), "no-store");
        let csp = header("content-security-policy");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(
            csp.contains("form-action 'self' https://app.example.com:8443"),
            "{csp}"
        );
    }
}
