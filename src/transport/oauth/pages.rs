//! The HTML pages the gateway itself shows a browser during login: the
//! notices for a login that cannot continue, and the frame the consent page
//! shares with them. Each names the gateway and the request id, so a user
//! who is stuck has something to quote and the operator something to search.

use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use url::Url;

use crate::auth::oauth::AuthFacade;
use crate::transport::request_id::GatewayRequestId;

const PAGE_STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:34rem;\
margin:4rem auto;padding:0 1rem;line-height:1.5}\
.meta{color:#555;font-size:.9rem;border-top:1px solid #ccc;margin-top:2rem;padding-top:1rem}\
.warn{border-left:4px solid #b45309;padding-left:.75rem}\
code{word-break:break-all}";

/// What every login page says about where the user is and whom to ask.
#[derive(Debug)]
pub(in crate::transport) struct PageContext {
    gateway_host: Option<String>,
    request_id: GatewayRequestId,
    support_contact: Option<String>,
}

impl PageContext {
    /// The host comes from `OIDC_REDIRECT_URL`, never the request's `Host`
    /// header: the page must name the gateway, not whatever the client sent.
    pub(in crate::transport) fn new(auth: &AuthFacade, request_id: GatewayRequestId) -> Self {
        let gateway_host = Url::parse(&auth.config.redirect_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned));
        let support_contact = auth
            .oidc
            .options()
            .support_contact
            .as_ref()
            .map(|contact| contact.as_str().to_owned());
        Self {
            gateway_host,
            request_id,
            support_contact,
        }
    }

    pub(in crate::transport) fn request_id(&self) -> GatewayRequestId {
        self.request_id
    }

    /// The closing block of a page, as HTML.
    pub(super) fn footer(&self) -> String {
        let gateway = match &self.gateway_host {
            Some(host) => format!("db-mcp-gateway at <strong>{}</strong>", escape_html(host)),
            None => "db-mcp-gateway".to_owned(),
        };
        let help = match &self.support_contact {
            Some(contact) => format!(
                "Need help? Contact <strong>{}</strong> and quote the request ID.",
                escape_html(contact)
            ),
            None => "Need help? Give the request ID to whoever runs this gateway.".to_owned(),
        };
        format!(
            "<p class=\"meta\">{gateway}<br>Request ID: <code>{}</code><br>{help}</p>",
            self.request_id
        )
    }
}

/// A page for a login that stopped. `heading` and `message` are plain text.
#[derive(Debug)]
pub(in crate::transport) struct Notice<'a> {
    pub(in crate::transport) status: StatusCode,
    pub(in crate::transport) heading: &'a str,
    pub(in crate::transport) message: &'a str,
    /// Where the waiting client is told the outcome; rendered as a link.
    pub(in crate::transport) return_to_client: Option<&'a str>,
}

impl Notice<'_> {
    pub(in crate::transport) fn render(&self, page: &PageContext) -> Response {
        let body = self.html(page);
        with_page_headers((self.status, Html(body)).into_response(), None)
    }

    fn html(&self, page: &PageContext) -> String {
        let heading = escape_html(self.heading);
        let message = escape_html(self.message);
        let link = self.return_to_client.map_or_else(String::new, |url| {
            format!(
                "<p><a href=\"{}\">Return to your application</a> to finish there.</p>",
                escape_html(url)
            )
        });
        let footer = page.footer();
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{heading}</title><style>{PAGE_STYLE}</style></head>\
<body><h1>{heading}</h1><p>{message}</p>{link}{footer}</body></html>"
        )
    }
}

/// `/auth/callback` found no pending login for the returned `state`: it
/// expired, was already used, or the gateway restarted mid-login. A 400 the
/// user can act on — never a 5xx, which reads as an outage.
pub(in crate::transport) fn login_expired(page: &PageContext) -> Response {
    Notice {
        status: StatusCode::BAD_REQUEST,
        heading: "Login session expired",
        message: "This sign-in took too long to complete, or was already used. Nothing is \
                  wrong with the service. Please start the connection again from your client \
                  (e.g. re-run the MCP authorization) and complete the sign-in without long \
                  pauses.",
        return_to_client: None,
    }
    .render(page)
}

/// The login store (the state DB) could not be read or written: nothing is
/// wrong with the sign-in itself, and it cannot be resumed from here.
pub(in crate::transport) fn login_unavailable(page: &PageContext) -> Response {
    Notice {
        status: StatusCode::SERVICE_UNAVAILABLE,
        heading: "Sign-in temporarily unavailable",
        message: "The gateway could not reach its own storage to finish this sign-in. Please \
                  start the connection again from your client in a moment.",
        return_to_client: None,
    }
    .render(page)
}

/// The IdP sent the browser back without a code on the bespoke login flow.
pub(in crate::transport) fn login_not_completed(page: &PageContext) -> Response {
    Notice {
        status: StatusCode::BAD_REQUEST,
        heading: "Sign-in not completed",
        message: "The identity provider did not complete the sign-in. Please start the \
                  connection again from your client.",
        return_to_client: None,
    }
    .render(page)
}

/// The IdP vouched for the user but not for their email. The client is only
/// ever told `access_denied`, so this page is where the user learns why.
pub(super) fn email_unverified(page: &PageContext, return_to_client: Option<&str>) -> Response {
    Notice {
        status: StatusCode::FORBIDDEN,
        heading: "Sign-in refused: email not verified",
        message: "Your identity provider did not send a verified email address for your \
                  account (the email was missing, or not marked as verified). Every database \
                  call is recorded under your email, so the gateway does not accept an \
                  unverified one. Verify your email with your identity provider, or ask its \
                  administrator to, then sign in again.",
        return_to_client,
    }
    .render(page)
}

/// A consent submission that cannot be tied to a live consent. Never
/// redirects: with no trusted flow there is no client redirect to send to.
pub(super) fn consent_rejected(page: &PageContext) -> Response {
    Notice {
        status: StatusCode::BAD_REQUEST,
        heading: "Authorization not completed",
        message: "This approval link expired or was already used. Start the connection \
                  again from your client.",
        return_to_client: None,
    }
    .render(page)
}

/// The paragraph a page shows a user who signed in with no groups at all.
pub(super) const NO_GROUPS_NOTICE: &str = "<p class=\"warn\">Your sign-in carried \
<strong>no groups</strong>. Database access here is granted by group, so you will \
probably see no databases. If you expected access, ask for your account to be added to \
the right group at your identity provider, then sign in again.</p>";

/// Headers for a gateway-rendered page: no framing (clickjacking a consent
/// button is the obvious attack), no scripts, no caching of one-time tokens,
/// and forms may post only here — and redirect only to `redirect_origin`.
pub(super) fn with_page_headers(mut response: Response, redirect_origin: Option<&str>) -> Response {
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

pub(super) fn escape_html(raw: &str) -> String {
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
#[path = "pages_tests.rs"]
mod tests;
