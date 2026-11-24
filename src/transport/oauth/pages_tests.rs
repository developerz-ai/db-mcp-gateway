use axum::body::to_bytes;
use axum::extract::Request;

use super::*;
use crate::auth::oidc::{LoginOptions, SupportContact};
use crate::auth::{AuthConfig, OidcClient};
use crate::transport::app_state::offline_for_tests;

fn page_context(redirect_url: &str, contact: Option<&str>) -> PageContext {
    let mut auth = offline_for_tests().oauth.auth;
    let config = AuthConfig {
        redirect_url: redirect_url.to_owned(),
        ..AuthConfig::default()
    };
    let options = LoginOptions {
        support_contact: contact.map(|raw| SupportContact::parse(raw).expect("valid contact")),
        ..LoginOptions::default()
    };
    auth.config = std::sync::Arc::new(config.clone());
    auth.oidc = OidcClient::with_options(config, options).expect("http client builds");
    PageContext::new(&auth, GatewayRequestId::of(&Request::default()))
}

async fn body_of(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8 page")
}

#[tokio::test]
async fn every_notice_names_the_gateway_the_request_and_the_contact() {
    let page = page_context(
        "https://db.internal.acme.com/auth/callback",
        Some("#data-platform"),
    );
    let request_id = page.request_id().to_string();
    let notices = [
        (
            login_expired(&page),
            StatusCode::BAD_REQUEST,
            "Login session expired",
        ),
        (
            login_not_completed(&page),
            StatusCode::BAD_REQUEST,
            "Sign-in not completed",
        ),
        (
            consent_rejected(&page),
            StatusCode::BAD_REQUEST,
            "Authorization not completed",
        ),
        (
            email_unverified(&page, None),
            StatusCode::FORBIDDEN,
            "Sign-in refused: email not verified",
        ),
    ];
    for (response, status, heading) in notices {
        assert_eq!(response.status(), status, "{heading}");
        let headers = response.headers().clone();
        assert!(
            headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html"),
            "{heading}"
        );
        assert_eq!(headers["cache-control"], "no-store", "{heading}");
        assert_eq!(headers["x-frame-options"], "DENY", "{heading}");
        let body = body_of(response).await;
        assert!(body.contains(&format!("<h1>{heading}</h1>")), "{body}");
        assert!(
            body.contains("db-mcp-gateway at <strong>db.internal.acme.com</strong>"),
            "{body}"
        );
        assert!(
            body.contains(&format!("Request ID: <code>{request_id}</code>")),
            "{body}"
        );
        assert!(
            body.contains("Contact <strong>#data-platform</strong> and quote the request ID."),
            "{body}"
        );
    }
}

#[tokio::test]
async fn without_a_contact_the_page_still_says_what_to_do_with_the_id() {
    let page = page_context("http://localhost:8443/auth/callback", None);
    let body = body_of(login_expired(&page)).await;
    assert!(
        body.contains("db-mcp-gateway at <strong>localhost</strong>"),
        "{body}"
    );
    assert!(
        body.contains("Give the request ID to whoever runs this gateway."),
        "{body}"
    );
    assert!(!body.contains("Contact <strong>"), "{body}");
}

#[tokio::test]
async fn unverified_email_page_says_so_and_links_back_to_the_client() {
    let page = page_context("https://gw.example/auth/callback", None);
    let back = "http://127.0.0.1:5000/cb?error=access_denied&state=a\"b";
    let body = body_of(email_unverified(&page, Some(back))).await;
    assert!(body.contains("not marked as verified"), "{body}");
    assert!(
        body.contains(
            "<a href=\"http://127.0.0.1:5000/cb?error=access_denied&amp;state=a&quot;b\">"
        ),
        "{body}"
    );
    assert!(
        !body_of(email_unverified(&page, None))
            .await
            .contains("<a href")
    );
}

#[tokio::test]
async fn operator_text_is_escaped() {
    let page = page_context("https://gw.example/auth/callback", Some("<b>ops</b> & co"));
    let body = body_of(login_expired(&page)).await;
    assert!(body.contains("&lt;b&gt;ops&lt;/b&gt; &amp; co"), "{body}");
    assert!(!body.contains("<b>ops"), "{body}");
}

#[tokio::test]
async fn an_unparseable_redirect_url_names_no_host() {
    let page = page_context("not a url", None);
    assert!(
        page.footer()
            .starts_with("<p class=\"meta\">db-mcp-gateway<br>")
    );
}

#[test]
fn escape_html_neutralises_markup() {
    assert_eq!(
        escape_html("<a href=\"x\">'&'</a>"),
        "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
    );
}

#[test]
fn page_headers_forbid_framing_and_caching() {
    let response = with_page_headers(
        Html("x").into_response(),
        Some("https://app.example.com:8443"),
    );
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
