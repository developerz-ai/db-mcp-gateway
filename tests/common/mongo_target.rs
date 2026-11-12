//! Fixtures for the target Mongo (`target-mongo`, :27018). The dev
//! container's `app` user is the root user and authenticates against `admin`.

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{MongoAdapter, PoolSizing};
use mongodb::Client;
use mongodb::bson::doc;
use mongodb::options::{ClientOptions, Credential, ServerAddress};
use uuid::Uuid;

pub const TARGET_HOST: &str = "localhost";
pub const TARGET_PORT: u16 = 27018;
pub const TARGET_USER: &str = "app";
pub const TARGET_PASSWORD: &str = "app-dev-only";
pub const TARGET_DB: &str = "app";

/// A mongo server named `name`, holding [`database`].
pub fn server(name: &str) -> Server {
    Server {
        name: name.to_string(),
        kind: ServerKind::Mongo,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: TARGET_PORT,
        tls: Tls::Insecure,
        tls_ca_file: None,
        pool: None,
        databases: vec![database()],
    }
}

pub fn database() -> Database {
    Database {
        name: TARGET_DB.to_string(),
        role: TARGET_USER.to_string(),
        password: Password::Literal(TARGET_PASSWORD.into()),
        description: String::new(),
        auth_database: Some("admin".to_string()),
        pool: None,
        write_role: None,
        write_password: None,
    }
}

pub async fn adapter(server_name: &str) -> MongoAdapter {
    MongoAdapter::open(
        &server(server_name),
        &database(),
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("target-mongo reachable; run `bin/dev up`")
}

/// Side-channel client for setup / teardown / inspection — bypasses the
/// rejector. NEVER a production path: it has root-equivalent access.
pub fn side_client() -> Client {
    let credential = Credential::builder()
        .username(TARGET_USER.to_string())
        .password(TARGET_PASSWORD.to_string())
        .source(Some("admin".to_string()))
        .build();
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: TARGET_HOST.to_string(),
            port: Some(TARGET_PORT),
        }])
        .credential(credential)
        .default_database(TARGET_DB.to_string())
        .build();
    Client::with_options(options).expect("side client builds")
}

/// Fresh collection name, so concurrent runs never share data.
pub fn unique_collection(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

/// Best-effort drop: a missing collection is not a test failure.
pub async fn drop_collection(client: &Client, collection: &str) {
    let _ = client
        .database(TARGET_DB)
        .run_command(doc! { "drop": collection })
        .await;
}
