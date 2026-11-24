//! Gateway consent for dynamically registered clients with a non-loopback
//! redirect (MCP security best practices, "Confused Deputy"). The IdP only ever
//! sees the gateway's static client, so its consent says nothing about who
//! receives the code; this page asks the signed-in user, after `/auth/callback`,
//! before any code is minted. See website/docs/initial-idea/04-auth-sso.md.

use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::{Extension, Form};
use serde::Deserialize;
use url::Url;

use super::super::app_state::OAuthState;
use super::bridge_login::issue_code;
use super::helpers::{oauth_error, random_token, redirect_with_error};
use super::pages::{
    NO_GROUPS_NOTICE, PageContext, consent_rejected, escape_html, with_page_headers,
};
use crate::auth::oauth::{AuthFacade, ClientName, GrantIdentity, OAuthBridge};
use crate::transport::request_id::GatewayRequestId;

/// Where the consent form posts. Mounted by `transport::router`.
pub(in crate::transport) const CONSENT_PATH: &str = "/authorize/consent";

/// Stash the verified login and render the consent page. Nothing reaches the
/// client until a valid `POST` [`CONSENT_PATH`] approves it.
pub(super) async fn request_consent(
    auth: &AuthFacade,
    identity: GrantIdentity,
    bridge: OAuthBridge,
    page: &PageContext,
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
    let html = consent_page(&ConsentView {
        email: &identity.email,
        no_groups: identity.groups.is_empty(),
        footer: &page.footer(),
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
    with_page_headers(Html(html).into_response(), Some(&target.origin))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentForm {
    consent_id: String,
    csrf: String,
    decision: Decision,
}

/// Both ids are bearer values for the pending consent.
impl std::fmt::Debug for ConsentForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentForm")
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

/// `POST /authorize/consent` — the user's answer. Approve mints the code and
/// 303s it to the client; deny 303s `access_denied` (RFC 6749 §4.1.2.1). An
/// unknown, expired, reused or CSRF-mismatched submission releases nothing.
pub async fn consent(
    State(state): State<OAuthState>,
    Extension(request_id): Extension<GatewayRequestId>,
    form: Result<Form<ConsentForm>, FormRejection>,
) -> Response {
    let page = PageContext::new(&state.auth, request_id);
    let Ok(Form(form)) = form else {
        return consent_rejected(&page);
    };
    let Some(pending) = state.auth.flows.take_consent(&form.consent_id).await else {
        return consent_rejected(&page);
    };
    if !pending.csrf_matches(&form.csrf) {
        tracing::warn!(%request_id, "consent submission with a mismatched CSRF token; flow discarded");
        return consent_rejected(&page);
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
    /// The login carried no groups: say so before the user approves.
    no_groups: bool,
    /// Pre-rendered HTML from [`PageContext::footer`].
    footer: &'a str,
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
    let no_groups = if view.no_groups { NO_GROUPS_NOTICE } else { "" };
    let footer = view.footer;
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Authorize application</title><style>\
body{{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;line-height:1.5}}\
.host{{font-size:1.4rem;font-weight:700;word-break:break-all}}\
.unverified,.meta{{color:#555;font-size:.9rem}}\
.meta{{border-top:1px solid #ccc;margin-top:2rem;padding-top:1rem}}\
.warn{{border-left:4px solid #b45309;padding-left:.75rem}}\
code{{word-break:break-all}}button{{font-size:1rem;padding:.5rem 1.25rem;margin-right:.75rem}}\
</style></head><body>\
<h1>Authorize database access?</h1>\
<p>You are signed in as <strong>{email}</strong>. An application is asking for \
access to the database gateway on your behalf. If you approve, your access will \
be sent to:</p>\
<p class=\"host\">{host}</p>{no_groups}\
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
</form>{footer}</body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_escapes_every_interpolated_value() {
        let page = consent_page(&ConsentView {
            email: "<script>e</script>",
            no_groups: false,
            footer: "",
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
            no_groups: false,
            footer: "<p class=\"meta\">footer</p>",
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
    fn redirect_target_splits_host_and_origin() {
        let target = RedirectTarget::parse("https://app.example.com:8443/cb").expect("valid");
        assert_eq!(target.host, "app.example.com");
        assert_eq!(target.origin, "https://app.example.com:8443");
    }

    #[test]
    fn a_login_without_groups_is_told_so_before_approving() {
        let view = |no_groups| ConsentView {
            email: "u@example.com",
            no_groups,
            footer: "<p class=\"meta\">footer</p>",
            client_id: "mcp-1",
            client_name: None,
            redirect_uri: "https://app.example/cb",
            redirect_host: "app.example",
            consent_id: "id",
            csrf: "tok",
        };
        let warned = consent_page(&view(true));
        assert!(warned.contains("<strong>no groups</strong>"), "{warned}");
        let notice = warned.find("no groups").expect("notice");
        let form = warned.find("<form").expect("form");
        assert!(notice < form, "the notice renders before the buttons");
        assert!(warned.ends_with("<p class=\"meta\">footer</p></body></html>"));
        assert!(!consent_page(&view(false)).contains("no groups"));
    }
}
