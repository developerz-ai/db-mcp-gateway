//! The MongoDB baseline path: the same JSON command, straight at MongoDB over
//! the mongodb driver.
//!
//! This is the mongo twin of [`crate::direct`]. Same discipline, same
//! non-negotiables:
//!
//! - A warm client with a pool sized to the driver's concurrency, so no
//!   request ever queues for a connection — queueing would be measured as
//!   latency and charged, wrongly, to the database.
//! - The **exact same command document** the gateway path sends. The gateway's
//!   `MongoAdapter` parses the command off the wire and dispatches it; this
//!   client dispatches the same document to the same server. Anything less
//!   would compare two different queries instead of two different paths.
//! - The cursor is fully drained before the clock stops, and an empty result
//!   is an error rather than a measurement.
//!
//! Credentials never appear in `Debug` or in any error text: the driver is
//! built from structured `Credential` fields (never a URI string), and the
//! `Debug` impl prints structural information only.

use std::time::Instant;

use crate::workload::{MONGO_COLLECTION, MONGO_KEY_FIELD, MONGO_SEED_DOCS, Shape};

/// The `authSource` used when a mongo URI names none.
///
/// Mongo's own default, and where the dev stack's container bootstrap puts
/// the `app` user's credentials. The URI's *path* names the database to
/// query — not the database the user authenticates against — and using it as
/// the auth source would fail with "Authentication failed", a failure that
/// looks like a wrong password rather than a wrong auth source.
const DEFAULT_MONGO_AUTH_SOURCE: &str = "admin";
use futures::StreamExt;
use mongodb::bson::{Document, doc};
use mongodb::error::Error as MongoError;
use mongodb::options::{ClientOptions, Credential, ServerAddress, Tls as MongoTls};
use mongodb::{Client, Database};

#[derive(Debug, thiserror::Error)]
pub enum MongoDirectError {
    // Stable bracketed prefix so a report consumer (or a `grep` over the
    // harness log) can classify failures without pattern-matching the
    // driver's prose, which changes between driver versions. Mirrors the
    // `[BENCH_DIRECT_*]` family on the postgres side.
    #[error("[BENCH_MONGO_DIRECT_DB] direct mongo access failed: {0}")]
    Db(#[from] MongoError),
    #[error("[BENCH_MONGO_DIRECT_CONFIG] mongo client configuration failed")]
    Config,
    /// The command succeeded but returned nothing. A benchmark measuring an
    /// empty result set is measuring a no-op.
    #[error(
        "[BENCH_MONGO_DIRECT_EMPTY_RESULT] shape {shape} returned no documents at iteration {iteration}"
    )]
    EmptyResult { shape: &'static str, iteration: u64 },
    /// The command document was not valid JSON, or not a JSON object.
    #[error(
        "[BENCH_MONGO_DIRECT_BAD_COMMAND] shape {shape} produced a command that is not a JSON object"
    )]
    BadCommand { shape: &'static str },
}

/// A direct-to-MongoDB client bound to one database.
pub struct MongoDirectClient {
    client: Client,
    database_name: String,
}

// Hand-written so the driver — whose `Debug` renders the parsed options
// including credentials — can never reach a log line. Mirrors the discipline
// of `crate::gateway::GatewayClient` and `src/exec/mongo::MongoAdapter`.
impl std::fmt::Debug for MongoDirectClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongoDirectClient")
            .field("database", &self.database_name)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl MongoDirectClient {
    /// Connect to `host:port` as `user`, authenticating against `auth_db`.
    ///
    /// Credentials are passed to the driver as structured fields — never
    /// concatenated into a URI — so a password containing `:` or `@` cannot
    /// rewrite the host segment. Same posture as the gateway's own
    /// `MongoAdapter::open`.
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        auth_db: &str,
        database: &str,
        concurrency: u32,
    ) -> Result<Self, MongoDirectError> {
        let credential = Credential::builder()
            .username(user.to_string())
            .password(password.to_string())
            .source(Some(auth_db.to_string()))
            .build();

        let mut options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: host.to_string(),
                port: Some(port),
            }])
            .credential(credential)
            .default_database(database.to_string())
            // Sized to the driver's concurrency so no request waits for a
            // connection. Queueing here would be charged to the database as
            // if it were gateway overhead.
            .max_pool_size(concurrency.max(1))
            .min_pool_size(concurrency.max(1))
            .build();
        // The dev target runs without TLS. The harness only ever points at
        // the local docker-compose stack, whose credentials are already
        // public in `docker-compose.dev.yml`.
        options.tls = Some(MongoTls::Disabled);

        let client = Client::with_options(options).map_err(|_| MongoDirectError::Config)?;
        Ok(MongoDirectClient {
            client,
            database_name: database.to_string(),
        })
    }

    fn database(&self) -> Database {
        self.client.database(&self.database_name)
    }

    /// Create and populate the benchmark collection.
    ///
    /// **Destructive.** Drops the collection first, so a re-run measures the
    /// same bytes rather than appending to the previous run's data. Point the
    /// harness at a disposable database only.
    ///
    /// The documents are deterministic — the numeric key is the loop index,
    /// `label` and `val` derive from it with the same arithmetic the postgres
    /// seed uses — so two runs on two machines execute over identical bytes.
    ///
    /// The key goes into [`MONGO_KEY_FIELD`], which is `_id`. MongoDB indexes
    /// `_id` on every collection it creates — that index is a property of the
    /// collection, not something this seed creates — so the point find is an
    /// index hit and the range find is an index range scan whose bounds and
    /// ordering both come from that one index. The seed drops the collection
    /// first, so the server creates the collection (and its `_id` index) again
    /// with the first insert; no extra index is created here, and none is
    /// needed: an explicit index on `_id` would be rejected by the server as a
    /// duplicate of the one it already has.
    pub async fn seed(&self) -> Result<(), MongoDirectError> {
        let collection = self.database().collection::<Document>(MONGO_COLLECTION);
        collection.drop().await?;

        let docs: Vec<Document> = (1..=MONGO_SEED_DOCS).map(seed_document).collect();

        collection.insert_many(docs).await?;

        // The aggregate shape filters on `val`, which is deliberately left
        // unindexed: it is a whole-collection scan on the mongo side. The
        // postgres `Aggregate` shape reads the same way in practice — its
        // `val > floor` predicate matches nearly every row, so postgres
        // plans a sequential scan rather than using the index on `val` —
        // so the two backends' aggregate figures stay comparable.
        Ok(())
    }

    /// Issue one command and return its wall-clock latency in milliseconds.
    ///
    /// Documents are fully drained and their fields touched before the clock
    /// stops. The driver would otherwise let us stop timing while the server
    /// is still streaming, making the baseline look faster than any real
    /// client could be — and inflating the gateway's apparent overhead.
    pub async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, MongoDirectError> {
        let command_text = shape.command(iteration);
        // Parsed exactly the way the gateway's own adapter parses it —
        // `serde_json::from_str` straight into a BSON `Document`. The direct
        // path and the gateway path therefore agree on the command document
        // byte for byte, and the driver's `Document` key order (which is
        // mongo's wire convention: first key = command name) is preserved.
        let command: Document =
            serde_json::from_str(&command_text).map_err(|_| MongoDirectError::BadCommand {
                shape: shape.name(),
            })?;

        let command_name = command
            .keys()
            .next()
            .ok_or(MongoDirectError::BadCommand {
                shape: shape.name(),
            })?
            .to_string();

        let started = Instant::now();
        let mut rows = 0usize;
        match command_name.as_str() {
            // Cursor-returning commands. The gateway's adapter uses
            // `run_cursor_command` for exactly these two, so the direct path
            // uses it too — same wire behaviour, same batching.
            "find" | "aggregate" => {
                let mut cursor = self.database().run_cursor_command(command).await?;
                while let Some(document) = cursor.next().await {
                    // `run_cursor_command` yields `Document`s directly. The
                    // field count is what gets touched so the drain cannot be
                    // optimised away.
                    let document = document?;
                    rows += document.len();
                }
            }
            // Scalar commands. The gateway's adapter uses `run_command` for
            // these; so does this path.
            "count" | "distinct" => {
                let response = self.database().run_command(command).await?;
                rows += response.len();
            }
            // The rejector allow-list is `find`/`aggregate`/`count`/`distinct`.
            // A command outside it is a harness bug, not a database problem —
            // report it against the shape, not the borrowed command name.
            _ => {
                return Err(MongoDirectError::BadCommand {
                    shape: shape.name(),
                });
            }
        }
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;

        // Keep the drain from being optimised into nothing, and catch a
        // silently-empty result set — the same no-op trap guarded on the
        // gateway side.
        if rows == 0 {
            return Err(MongoDirectError::EmptyResult {
                shape: shape.name(),
                iteration,
            });
        }

        Ok(elapsed)
    }

    pub async fn close(&self) {
        // `shutdown` takes the client by value. `mongodb::Client` is a cheap
        // handle over an `Arc`, so cloning it to shut the shared pool down
        // costs nothing and keeps `close(&self)`.
        self.client.clone().shutdown().await;
    }
}

/// One seeded benchmark document, keyed by its loop index.
///
/// The numeric key goes into [`MONGO_KEY_FIELD`] — `_id`, mongo's primary
/// key. `_id` is the only field mongo indexes on every collection, so it is
/// the only field the find shapes may filter or sort on: a filter on any
/// other field is a collection scan over all the documents, and a sort on any
/// other field adds a blocking in-memory sort on top of it. With the key in
/// `_id` the point find is an index hit and the range find is an index range
/// scan whose bounds and ordering both come from that one index.
///
/// The key is written through [`MONGO_KEY_FIELD`] rather than as a literal,
/// so the seed and the shapes that query it name the same field by
/// construction. A literal here would let the constant and the seed drift
/// apart silently, and the drift is invisible in the numbers: the shapes
/// would still return the right rows, just by a collection scan.
fn seed_document(g: i64) -> Document {
    doc! {
        (MONGO_KEY_FIELD): g,
        "label": format!("label-{g}"),
        "val": (g * 7919) % 100000,
    }
}

/// Split a mongo URI into the pieces the direct client needs.
///
/// Deliberately a small parser rather than a URL library: the harness needs
/// exactly five fields and must never echo the password back. The password is
/// returned to the caller only, and never reaches a log line or a `Debug`
/// impl — the client holds it as a driver credential.
///
/// A mongo URI without credentials falls back to the dev stack's public
/// credentials, which `docker-compose.dev.yml` already publishes.
///
/// A `mongodb+srv://` URI is rejected: it needs DNS SRV discovery, which this
/// parser does not implement and the driver here is not built for — the host
/// goes in as a literal TCP address. Accepting the scheme would quietly point
/// the client at the SRV hostname on port 27017 and never resolve anything.
pub fn parse_mongo_url(url: &str) -> anyhow::Result<(String, u16, String, String, String)> {
    if url.starts_with("mongodb+srv://") {
        anyhow::bail!(
            "mongodb+srv:// is not supported by the direct baseline — it needs DNS SRV \
             discovery, which this local-only harness does not implement; pass a \
             mongodb:// URI with an explicit host and port"
        );
    }
    let rest = url
        .strip_prefix("mongodb://")
        .ok_or_else(|| anyhow::anyhow!("mongo URL must start with `mongodb://`"))?;

    // Split off the path — the default database. The harness is told the
    // database to query separately (`--mongo-database`), so the path is only
    // needed to find where the authority ends.
    let authority = match rest.find('/') {
        Some(index) => &rest[..index],
        None => rest,
    };

    // Split off the query string.
    let authority = authority.split('?').next().unwrap_or(authority);

    let (credentials, hostport) = match authority.rfind('@') {
        Some(index) => (Some(&authority[..index]), &authority[index + 1..]),
        None => (None, authority),
    };

    let (user, password) = match credentials {
        Some(creds) => {
            let (user, password) = creds.split_once(':').unwrap_or((creds, ""));
            (percent_decode(user), percent_decode(password))
        }
        None => ("app".to_string(), "app-dev-only".to_string()),
    };

    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("mongo URL has an invalid port"))?,
        ),
        None => (hostport.to_string(), 27017),
    };

    // `authSource` in the query string, else `admin`.
    //
    // The `admin` default is mongo's own convention when a URI names no
    // `authSource`, and it is what the dev stack's container bootstrap
    // creates: the `app` user is the container's root user, whose credentials
    // live in `admin`. Using the URI's *path* database instead would
    // authenticate against a database the user was never created in, and
    // mongo would answer "Authentication failed" — a failure that looks
    // like a wrong password rather than a wrong auth source.
    let auth_db = if let Some(query) = rest.split_once('?').map(|(_, q)| q) {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix("authSource="))
            .map(percent_decode)
            .unwrap_or_else(|| DEFAULT_MONGO_AUTH_SOURCE.to_string())
    } else {
        DEFAULT_MONGO_AUTH_SOURCE.to_string()
    };

    Ok((host, port, user, password, auth_db))
}

/// Minimal percent-decoding for URI userinfo and query values.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_plain_mongo_uri_is_split_into_its_parts() {
        let (host, port, user, password, auth_db) =
            parse_mongo_url("mongodb://app:app-dev-only@localhost:27018/app").expect("parses");
        assert_eq!(host, "localhost");
        assert_eq!(port, 27018);
        assert_eq!(user, "app");
        assert_eq!(password, "app-dev-only");
        // The path names the database to QUERY; the auth source is where the
        // user's credentials live — `admin` for the dev stack's container
        // bootstrap. Authenticating against the path's database would fail.
        assert_eq!(auth_db, "admin");
    }

    #[test]
    fn an_auth_source_in_the_query_wins() {
        let (_, _, _, _, auth_db) =
            parse_mongo_url("mongodb://app:pw@localhost:27018/app?authSource=admin")
                .expect("parses");
        assert_eq!(auth_db, "admin");
    }

    #[test]
    fn a_uri_without_a_path_authenticates_against_admin() {
        let (_, port, _, _, auth_db) =
            parse_mongo_url("mongodb://app:pw@localhost:27017").expect("parses");
        assert_eq!(port, 27017);
        assert_eq!(auth_db, "admin");
    }

    #[test]
    fn a_uri_without_credentials_falls_back_to_the_dev_stack_defaults() {
        let (_, _, user, password, _) =
            parse_mongo_url("mongodb://localhost:27018/app").expect("parses");
        assert_eq!(user, "app");
        assert_eq!(password, "app-dev-only");
    }

    #[test]
    fn a_non_mongo_uri_is_rejected() {
        assert!(parse_mongo_url("postgres://localhost/app").is_err());
    }

    /// An SRV URI is rejected, not silently treated as a literal TCP host on
    /// port 27017 — connecting that way would never resolve the SRV records
    /// and could never reach an SRV-only deployment.
    #[test]
    fn an_srv_uri_is_rejected_rather_than_treated_as_a_tcp_host() {
        let err = parse_mongo_url("mongodb+srv://cluster.example.com/app")
            .expect_err("srv URIs are rejected");
        assert!(err.to_string().contains("mongodb+srv"), "{err}");
    }

    use super::*;
    use mongodb::bson::Bson;
    use serde_json::Value;

    /// Build a client holding a password, without touching the network.
    /// `Client::with_options` does not open a connection — the first
    /// operation does — so this is safe in a unit test.
    fn client_with_password(password: &str) -> MongoDirectClient {
        let credential = Credential::builder()
            .username("app".to_string())
            .password(password.to_string())
            .source(Some("admin".to_string()))
            .build();
        let options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: "localhost".to_string(),
                port: Some(27018),
            }])
            .credential(credential)
            .default_database("app".to_string())
            .build();
        MongoDirectClient {
            client: Client::with_options(options).expect("options are valid"),
            database_name: "app".to_string(),
        }
    }

    /// The seed must put the numeric key in the field the find shapes
    /// actually query.
    ///
    /// `_id` is the only field mongo indexes on every collection. If the
    /// seed wrote the key into some other field, the point find would be a
    /// collection scan over every document and the range find would add a
    /// blocking in-memory sort — the shapes would measure mongo's planner
    /// instead of the gateway's overhead. This test is the guard that the
    /// seeded document and the query agree on the same field.
    #[test]
    fn seed_document_keys_the_indexed_field() {
        let document = seed_document(42);
        assert_eq!(
            document.get(MONGO_KEY_FIELD),
            Some(&Bson::Int64(42)),
            "the numeric key must live in `{MONGO_KEY_FIELD}`"
        );
        // And nothing else may hold it: a second copy of the key in an
        // unindexed field is exactly the trap this guards against.
        assert_eq!(
            document.keys().collect::<Vec<_>>(),
            vec![MONGO_KEY_FIELD, "label", "val"],
            "the document must carry the key once, in `{MONGO_KEY_FIELD}`"
        );
    }

    /// The field the seed keys on must be the field mongo indexes on every
    /// collection.
    ///
    /// The guard above proves the seed and the shapes agree; this one proves
    /// that the field they agree on is `_id`. If it ever stopped being, the
    /// "indexed point find" and "indexed range find" claims would become
    /// false while every other test kept passing — a collection scan over
    /// 50k documents still returns the right rows.
    #[test]
    fn the_keyed_field_is_the_one_mongo_indexes_by_default() {
        assert_eq!(
            MONGO_KEY_FIELD, "_id",
            "the seeded key must live in `_id` — the only field mongo indexes \
             on every collection"
        );
    }

    /// The driver's own `Debug` renders the parsed options, credentials
    /// included. The harness must never print them.
    ///
    /// Async because `Client::with_options` requires a Tokio runtime — the
    /// driver installs its I/O reactor on construction. No connection is
    /// opened: the first *operation* does that.
    #[tokio::test]
    async fn debug_output_never_contains_credentials() {
        let client = client_with_password("super-secret-mongo-pw");
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("super-secret-mongo-pw"),
            "Debug leaked the password: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// The mongo command the harness sends must be a JSON object whose first
    /// key is the command name — the same wire convention the gateway's
    /// rejector relies on. If this drifts, the direct path would dispatch a
    /// different command than the gateway path.
    #[test]
    fn every_mongo_shape_produces_a_dispatchable_command() {
        for shape in crate::workload::Shape::for_backend(crate::workload::Backend::Mongo) {
            let text = shape.command(7);
            let value: Value = serde_json::from_str(&text).expect("valid JSON");
            let object = value.as_object().expect("JSON object");
            let first = object.keys().next().expect("has a command name");
            assert!(
                ["find", "aggregate", "count", "distinct"].contains(&first.as_str()),
                "{} produced `{first}`",
                shape.name()
            );
            // And the driver's `Document` conversion must accept it — parsed
            // the same way the gateway's adapter parses the command.
            let document: Document =
                serde_json::from_str(&text).expect("the driver accepts the command");
            assert_eq!(
                document.keys().next().expect("has a command name"),
                first,
                "the driver's key order must match the JSON's"
            );
        }
    }
}
