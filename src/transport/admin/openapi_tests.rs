//! The OpenAPI document and the router agree, both ways:
//! - every documented `(method, path)` reaches a handler (anything but the
//!   router's 404/405), and every method the document leaves out of a
//!   documented path is refused with 405;
//! - every path literal the router module mounts is documented.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use super::DOCUMENT;
use crate::auth::{Identity, IdentityKind, SessionId, SessionStore};
use crate::authz::PermissionsCache;
use crate::config::{AdminGroup, ConfigFile};
use crate::state::permissions::pg::PgPermissionsRepo;
use crate::transport::admin::{AdminDeps, router};

const METHODS: [&str; 5] = ["get", "post", "patch", "put", "delete"];

fn documented() -> BTreeSet<(String, String)> {
    let doc: Value = serde_json::from_str(DOCUMENT).expect("openapi.json is JSON");
    assert_eq!(doc["openapi"], "3.1.0");
    let paths = doc["paths"].as_object().expect("paths");
    paths
        .iter()
        .flat_map(|(path, item)| {
            let item = item.as_object().expect("path item");
            item.keys()
                .filter(|k| METHODS.contains(&k.as_str()))
                .map(|m| (m.clone(), path.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn concrete(path: &str) -> String {
    path.replace("{id}", "00000000-0000-0000-0000-000000000000")
}

fn admin_router() -> axum::Router {
    // Never connects: a handler that reaches for the DB fails fast, which is
    // still "mounted".
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(10))
        .connect_lazy("postgres://u:p@127.0.0.1:1/none")
        .expect("lazy pool");
    let repo = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let config = ConfigFile::from_yaml_str("{}").expect("empty config");
    router(AdminDeps {
        group: AdminGroup::new("admins").expect("group"),
        repo: repo.clone(),
        state_db: pool.clone(),
        cache: PermissionsCache::new(repo, Duration::from_secs(1)),
        sessions: SessionStore::new(pool),
        max_session_age: None,
        known_servers: Arc::from(Vec::<String>::new()),
        config: Arc::new(ArcSwap::from_pointee(config)),
    })
}

async fn status(app: &axum::Router, method: &str, path: &str) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::from_bytes(method.to_uppercase().as_bytes()).expect("method"))
        .uri(concrete(path))
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(Identity {
        session_id: SessionId::new(),
        user_sub: "admin".into(),
        user_email: "admin@example.com".into(),
        groups: vec!["admins".into()],
        issued_at: chrono::Utc::now(),
        kind: IdentityKind::Sso,
    });
    app.clone()
        .oneshot(request)
        .await
        .expect("infallible")
        .status()
}

#[tokio::test]
async fn every_documented_operation_is_mounted_and_no_other_method_is() {
    let app = admin_router();
    let documented = documented();
    let paths: BTreeSet<&String> = documented.iter().map(|(_, p)| p).collect();
    for path in paths {
        for method in METHODS {
            let got = status(&app, method, path).await;
            if documented.contains(&(method.to_string(), path.clone())) {
                assert!(
                    !matches!(got, StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND),
                    "{method} {path} is documented but not mounted ({got})"
                );
            } else {
                assert_eq!(
                    got,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path} is mounted but undocumented"
                );
            }
        }
    }
}

#[test]
fn every_mounted_path_is_documented() {
    let source = include_str!("mod.rs");
    let documented: BTreeSet<String> = documented().into_iter().map(|(_, p)| p).collect();
    let mounted: BTreeSet<String> = source
        .split('"')
        .filter(|s| s.starts_with("/admin/v1/"))
        .map(|s| s.replace(":id", "{id}"))
        .collect();
    assert!(!mounted.is_empty());
    assert_eq!(mounted, documented, "router paths vs openapi.json paths");
}
