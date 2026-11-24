//! Property tests for the two untrusted text inputs at the edges: any bytes
//! POSTed to `/mcp` get a stable, non-5xx answer (never a panic or a hang),
//! and a config YAML that fails to parse never echoes a secret it carried
//! (MUST #1: no credential in an error).

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::transport;
use proptest::prelude::*;
use serde_json::Value;
use tower::ServiceExt;

use crate::common::gateway::authless_state;

/// Bytes an agent (or an attacker) might send: JSON-shaped fragments
/// spliced together, and raw noise.
fn body() -> impl Strategy<Value = Vec<u8>> {
    let fragment = prop::sample::select(vec![
        "{",
        "}",
        "[",
        "]",
        ",",
        ":",
        "\"jsonrpc\"",
        "\"2.0\"",
        "\"id\"",
        "1",
        "null",
        "\"method\"",
        "\"tools/call\"",
        "\"tools/list\"",
        "\"initialize\"",
        "\"params\"",
        "{\"name\":\"run_query\"}",
        "1e999",
        "-0",
        "\"\\ud800\"",
        "true",
        " ",
    ]);
    prop_oneof![
        prop::collection::vec(fragment, 0..24).prop_map(|parts| parts.concat().into_bytes()),
        prop::collection::vec(any::<u8>(), 0..256),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn any_bytes_on_mcp_get_a_non_5xx_answer(bytes in body()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (status, body) = runtime.block_on(async {
            let router = transport::test_router(&Config::default(), authless_state());
            let request = Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(bytes.clone()))
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let status = response.status();
            (status, to_bytes(response.into_body(), 1 << 20).await.unwrap())
        });
        prop_assert!(!status.is_server_error(), "{status} for {:?}", String::from_utf8_lossy(&bytes));
        if status != StatusCode::ACCEPTED && !body.is_empty() {
            prop_assert!(
                serde_json::from_slice::<Value>(&body).is_ok(),
                "non-JSON answer {:?}",
                String::from_utf8_lossy(&body)
            );
        }
    }
}

/// A valid config with `secret` as a literal database password.
fn config_with(secret: &str) -> String {
    format!(
        "servers:\n  - name: s\n    kind: postgres\n    host: h\n    port: 5432\n    \
         databases:\n      - name: d\n        role: r\n        password: {secret}\n\
         permissions: []\n"
    )
}

/// Ways an operator breaks a config while the secret sits in it.
fn broken(secret: &str, mutation: usize, cut: usize) -> String {
    let good = config_with(secret);
    match mutation % 6 {
        0 => good.replace("port: 5432", &format!("port: {secret}")),
        1 => good.replace("password:", "passwrd:"),
        2 => good.replace("role: r", &format!("role: [{secret}")),
        3 => good.replace("        password", "  password"),
        4 => format!("{good}{secret}: {secret}\n"),
        _ => {
            good[..good.find(secret).unwrap_or(0) + cut % (secret.len() + 1)].to_string()
                + "\n  - {"
        }
    }
}

/// Everything `main` would print: Display, Debug and the source chain.
fn rendered(err: &dyn std::error::Error) -> String {
    let mut text = format!("{err}\n{err:?}");
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(&format!("\n{cause}\n{cause:?}"));
        source = cause.source();
    }
    text
}

proptest! {
    #[test]
    fn a_config_parse_error_never_echoes_a_planted_secret(
        secret in "s3cr3t[A-Za-z0-9]{10,20}",
        mutation in any::<usize>(),
        cut in any::<usize>(),
    ) {
        let yaml = broken(&secret, mutation, cut);
        if let Err(err) = ConfigFile::from_yaml_str(&yaml) {
            let text = rendered(&err);
            prop_assert!(!text.contains(&secret), "secret echoed for\n{yaml}\n---\n{text}");
        }
    }
}

/// The property above is not vacuous: the unbroken config parses, and every
/// mutation is a parse error.
#[test]
fn every_mutation_breaks_the_config() {
    let secret = "s3cr3tAbCdEfGhIj";
    assert!(ConfigFile::from_yaml_str(&config_with(secret)).is_ok());
    for mutation in 0..6 {
        let yaml = broken(secret, mutation, 4);
        assert!(ConfigFile::from_yaml_str(&yaml).is_err(), "parsed:\n{yaml}");
    }
}
