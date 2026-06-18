//! MongoDB target adapter — scaffold + read-only enforcement (#57).
//!
//! Wire-shape: [`MongoAdapter`] implements [`super::DbAdapter`] and is
//! dispatched to by [`super::AdapterRegistry`] when `server.kind` is
//! [`crate::config::ServerKind::Mongo`]. Tools never see the concrete
//! type — they only see `Arc<dyn DbAdapter>` from the registry, identical
//! to the pg path.
//!
//! This issue ships *no execution*. The trait's `execute` runs the
//! [`rejector`] first; if the command passes, it returns
//! [`super::ExecError::NotImplemented`] — the typed "scaffold gap" marker.
//! #58 replaces that branch with the real mongo client call.
//!
//! Security-required (CLAUDE.md). The connection password is *never*
//! embedded in `Display` for any error or in any tracing field, identical
//! to the pg adapter discipline (`PgAdapter::Debug` redaction pattern).
//! Credentials are passed to the driver as structured `Credential` fields
//! (not concatenated into a URI), so no encoding bug can turn a
//! `:`-bearing password into URI structure. See [`MongoAdapter::open`].

pub mod rejector;

use async_trait::async_trait;
use mongodb::Client;
use mongodb::options::{ClientOptions, Credential, ServerAddress, Tls as MongoTls, TlsOptions};

use crate::config::{Database, Server, Tls};

use super::adapter::{AdapterKind, DbAdapter, ExecError, ExecQuery, ExecResult};
use super::pg::resolve_password;

/// Per-`(server, database)` mongo adapter. Wraps a `mongodb::Client`; one
/// instance per logical DB so a slow query on DB A can never block DB B.
pub struct MongoAdapter {
    client: Client,
    /// Composite label for metrics tagging — bounded cardinality, supplied
    /// from YAML config rather than user input.
    db_label: String,
}

impl std::fmt::Debug for MongoAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `mongodb::Client`'s `Debug` would render the parsed options
        // including credentials. Never let that leak — print structural
        // info only. Same posture as `PgAdapter::Debug`.
        f.debug_struct("MongoAdapter")
            .field("db", &self.db_label)
            .finish()
    }
}

impl MongoAdapter {
    /// Open a fresh mongo client for `(server, database)`. Lazy in the
    /// network sense: building `ClientOptions` doesn't open a TCP
    /// connection; the first operation does. Same posture as
    /// `PgAdapter::open` — misconfiguration surfaces on first use, not at
    /// boot.
    pub async fn open(server: &Server, database: &Database) -> Result<Self, ExecError> {
        let password = resolve_password(&database.password)?;

        // Structured credentials avoid any URI-string assembly: a
        // password containing `:` or `@` can't accidentally rewrite the
        // host segment because the driver receives username/password as
        // separate fields. Same posture as sqlx's `PgConnectOptions`.
        let credential = Credential::builder()
            .username(database.role.clone())
            .password(password)
            .source(Some(database.name.clone()))
            .build();

        let mut options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: server.host.clone(),
                port: Some(server.port),
            }])
            .credential(credential)
            .default_database(database.name.clone())
            .build();
        if matches!(server.tls, Tls::Required) {
            options.tls = Some(MongoTls::Enabled(TlsOptions::default()));
        }

        let client = Client::with_options(options).map_err(|_| ExecError::Connection)?;
        let db_label = format!("{}/{}", server.name, database.name);
        Ok(Self { client, db_label })
    }
}

#[async_trait]
impl DbAdapter for MongoAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Mongo
    }

    /// Read-only enforcement first; *then* execution would happen — except
    /// execution isn't implemented in #57. The rejector lives in
    /// [`rejector::validate_command`]; on accept, return the typed
    /// "scaffold gap" marker so callers see a clear error rather than a
    /// generic failure. #58 replaces the `NotImplemented` branch with a
    /// `mongodb::Database::run_command` call.
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        rejector::validate_command(query.sql).map_err(|_| ExecError::Sql)?;
        Err(ExecError::NotImplemented {
            adapter: AdapterKind::Mongo,
            op: "execute",
        })
    }

    /// Cheap liveness probe — ping the admin database. Same role as pg's
    /// `SELECT 1`: confirms the client can hand out a working connection
    /// and the server is responding. Costs one round-trip.
    async fn health(&self) -> Result<(), ExecError> {
        use mongodb::bson::doc;
        self.client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
            .map(|_| ())
            .map_err(|_| ExecError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Password, ServerKind};

    fn server_for(host: &str, port: u16, tls: Tls) -> Server {
        Server {
            name: "mongo".to_string(),
            kind: ServerKind::Mongo,
            description: String::new(),
            host: host.to_string(),
            port,
            tls,
            databases: vec![],
        }
    }

    fn database_for(name: &str, role: &str, password: &str) -> Database {
        Database {
            name: name.to_string(),
            role: role.to_string(),
            password: Password::Literal(password.to_string()),
            description: String::new(),
        }
    }

    /// `MongoAdapter::Debug` must NEVER include the client (which renders
    /// the parsed `ClientOptions` including credentials). Mirrors the
    /// `PgAdapter` redaction test in `pg.rs`.
    #[tokio::test]
    async fn debug_does_not_leak_credentials() {
        let s = server_for("localhost", 27017, Tls::Required);
        let d = database_for("app", "the_user", "super_secret_pw");
        let adapter = MongoAdapter::open(&s, &d).await.expect("client constructs");
        let rendered = format!("{adapter:?}");
        assert!(rendered.contains("mongo/app"));
        assert!(
            !rendered.contains("super_secret_pw"),
            "leaked password: {rendered}"
        );
        assert!(!rendered.contains("the_user"), "leaked role: {rendered}");
    }
}
