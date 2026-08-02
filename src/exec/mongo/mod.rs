//! MongoDB target adapter — read-only enforcement + command execution.
//!
//! Wire-shape: [`MongoAdapter`] implements [`super::DbAdapter`] and is
//! dispatched to by [`super::AdapterRegistry`] when `server.kind` is
//! [`crate::config::ServerKind::Mongo`]. Tools never see the concrete
//! type — they only see `Arc<dyn DbAdapter>` from the registry, identical
//! to the pg path.
//!
//! `execute` runs the [`rejector`] first; only an accepted read command
//! reaches the driver, and it reaches it under the gateway's always-present
//! time budget ([`super::adapter::effective_timeout_ms`]) — see
//! [`MongoAdapter::execute`] for the timeout / cancellation contract.
//!
//! Security-required (CLAUDE.md). The connection password is *never*
//! embedded in `Display` for any error or in any tracing field, identical
//! to the pg adapter discipline (`PgAdapter::Debug` redaction pattern).
//! Credentials are passed to the driver as structured `Credential` fields
//! (not concatenated into a URI), so no encoding bug can turn a
//! `:`-bearing password into URI structure. See [`MongoAdapter::open`].

mod cancel;
pub mod rejector;

use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt;
use mongodb::Client;
use mongodb::bson::{Bson, Document};
use mongodb::error::{Error as MongoError, ErrorKind};
use mongodb::options::{ClientOptions, Credential, ServerAddress, Tls as MongoTls, TlsOptions};
use secrecy::ExposeSecret;
use serde_json::Value;

use crate::config::{Database, Server, Tls};

use super::adapter::{
    AdapterKind, DbAdapter, ExecError, ExecQuery, ExecResult, TOKIO_TIMEOUT_SLACK_MS,
    effective_timeout_ms,
};
use super::pg::resolve_password;

/// Per-`(server, database)` mongo adapter. Wraps a `mongodb::Client`; one
/// instance per logical DB so a slow query on DB A can never block DB B.
pub struct MongoAdapter {
    client: Client,
    /// Composite label for metrics tagging — bounded cardinality, supplied
    /// from YAML config rather than user input.
    db_label: String,
    /// Default database the adapter dispatches commands against — derived
    /// from the YAML `databases[].name` at construction. The mongo wire
    /// protocol needs the database explicitly on every `run_command`;
    /// stashing it here keeps the per-request dispatch lookup-free.
    database_name: String,
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
        let password = resolve_password(&database.password).await?;

        // Structured credentials avoid any URI-string assembly: a
        // password containing `:` or `@` can't accidentally rewrite the
        // host segment because the driver receives username/password as
        // separate fields. Same posture as sqlx's `PgConnectOptions`.
        // `authSource` controls which database mongo verifies the role
        // against. Operators pick this per their deployment:
        //   - `None` (default) → fall back to `database.name`: the
        //     least-privilege per-db user pattern spec 12 §237 calls out.
        //   - `Some("admin")` → cross-db user (mongo's container bootstrap
        //     pattern, common in dev / quickstart setups).
        let credential = Credential::builder()
            .username(database.role.clone())
            // The driver boundary: expose the plaintext only here, where mongo's
            // `Credential` takes ownership of its own `String` copy.
            .password(password.expose_secret().to_owned())
            .source(Some(
                database
                    .auth_database
                    .clone()
                    .unwrap_or_else(|| database.name.clone()),
            ))
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
        let database_name = database.name.clone();
        Ok(Self {
            client,
            db_label,
            database_name,
        })
    }
}

#[async_trait]
impl DbAdapter for MongoAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Mongo
    }

    /// Read-only enforcement first; on accept, dispatch the parsed BSON
    /// command to the mongo driver under the gateway's time budget.
    ///
    /// A rejected command maps to [`ExecError::Forbidden`] (→ tool code
    /// `forbidden_sql`), matching the pg path's `sql_guard::is_read_only`
    /// posture. Per spec 03, this is a policy denial, not a syntax error.
    ///
    /// **Timeout** — identical semantics to `PgAdapter::execute`. The budget
    /// is [`effective_timeout_ms`]: always present, and clamped so a grant
    /// can only tighten it. It is applied twice, because neither half is
    /// sufficient alone:
    ///
    /// - `maxTimeMS` on the command, so mongo kills the operation
    ///   server-side and we get the precise `MaxTimeMSExpired` (code 50) →
    ///   [`ExecError::Timeout`] mapping.
    /// - A `tokio::time::timeout` around the whole dispatch *including the
    ///   cursor drain*, because `maxTimeMS` does not reliably reach the
    ///   `getMore` round-trips that drain the rest of the cursor (mongo
    ///   carries an aggregation cursor's deadline into `getMore`; a `find`
    ///   cursor's is not covered), so a large result set would otherwise
    ///   blow straight through the budget.
    ///
    /// **Cancellation** — best-effort server-side kill of the *initial*
    /// command phase via `cancel::KillOpOnDrop` (#141), the mongo analogue
    /// of the pg path's `pg_cancel_backend` drop guard. Every command is
    /// stamped with a unique `comment` marker before dispatch; if the
    /// future is dropped mid-operation (agent disconnect), the guard's
    /// `Drop` spawns a detached `currentOp` lookup by that marker followed
    /// by `killOp` on every matching `opid` (a `mongos` fan-out surfaces
    /// one entry per shard). A disconnect during the *cursor drain* is
    /// covered by the driver's own `killCursors` on `Cursor::drop`, not by
    /// this guard — the marker rides on the initial `find` / `aggregate`
    /// but each `getMore` round-trip is a fresh operation with no marker
    /// to find. Three things keep even the initial-phase kill short of a
    /// guarantee (see `cancel` module docs for the full rationale):
    /// `killOp` and `currentOp` (with `$ownOps: false`) both require
    /// cluster-admin privileges the least-privilege mongo role doesn't
    /// have by default, the `currentOp` lookup can race a very short-lived
    /// operation's own registration, and only the initial command is
    /// targeted. Either way `maxTimeMS` remains the hard backstop. (The
    /// `outcome: cancelled` audit row is unaffected: it is written by the
    /// backend-agnostic drop guard in `tools::audit_dispatch`.)
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        rejector::validate_command(query.sql)
            .map_err(|err| ExecError::Forbidden(err.to_string()))?;

        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        match tokio::time::timeout(budget, self.dispatch(&query, effective_ms)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
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

impl MongoAdapter {
    /// Parse, stamp the DB-side budget, and run one already-accepted command.
    /// Split out of [`DbAdapter::execute`] so the `tokio::time::timeout`
    /// there covers the cursor drain as well as the initial dispatch.
    async fn dispatch(
        &self,
        query: &ExecQuery<'_>,
        effective_ms: u32,
    ) -> Result<ExecResult, ExecError> {
        let mut cmd: Document = serde_json::from_str(query.sql).map_err(|_| ExecError::Sql)?;
        let command_name = first_command_name(&cmd).ok_or(ExecError::Sql)?;

        // Unconditional: `insert` overwrites, so a caller-supplied
        // `maxTimeMS` in the raw command can only ever be replaced by the
        // gateway's clamped value — it can't be used to buy more budget.
        cmd.insert("maxTimeMS", i64::from(effective_ms));
        // Marker for the cancel guard's `currentOp` lookup — see
        // `cancel::stamp_marker` and this method's own doc comment above.
        let marker = cancel::stamp_marker(&mut cmd);
        let mut kill_guard = cancel::KillOpOnDrop::armed(self.client.clone(), marker);

        let started = Instant::now();
        let db = self.client.database(&self.database_name);

        // Wrapped in a block so `?` inside each arm exits the block (captured
        // into `result`) rather than this function — an early function return
        // would skip `kill_guard.disarm()` below. Harmless either way (the
        // guard is best-effort: a currentOp lookup against an already-errored
        // operation just finds nothing), but disarming on every normal
        // completion — success or typed error — is the correct target, same
        // posture as `pg::run_query_inner`'s `CancelOnDrop`.
        let result: Result<ExecResult, ExecError> = async {
            match command_name.as_str() {
                // Cursor-returning commands. `run_cursor_command` handles the
                // initial response *and* follow-up `getMore` calls so we can
                // drain past the first batch when the user asks for more rows.
                "find" | "aggregate" => {
                    let mut cursor = db.run_cursor_command(cmd).await.map_err(classify)?;
                    let limit = query.row_limit as usize;
                    let mut rows: Vec<Vec<Value>> = Vec::new();
                    let mut truncated = false;
                    while let Some(doc_result) = cursor.next().await {
                        if rows.len() >= limit {
                            truncated = true;
                            break;
                        }
                        let doc = doc_result.map_err(classify)?;
                        rows.push(vec![doc_to_json(doc)]);
                    }
                    Ok(ExecResult {
                        columns: vec!["document".to_string()],
                        rows,
                        truncated,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }
                // Scalar commands. The response shape carries the answer in
                // a single field that's documented per command name.
                "count" => {
                    let response = db.run_command(cmd).await.map_err(classify)?;
                    let n = response
                        .get_i64("n")
                        .or_else(|_| response.get_i32("n").map(i64::from));
                    // `row_limit == 0` is a valid grant constraint (authz
                    // proptests generate it) and the exec invariant is
                    // "never emit more rows than configured" — the cursor
                    // arms above honor it implicitly via `rows.len() >= limit`
                    // / `.take(limit)`; the scalar arm has to do it explicitly
                    // because its result shape is fixed at one row.
                    let (rows, truncated) = if query.row_limit == 0 {
                        (Vec::new(), true)
                    } else {
                        let value = match n {
                            Ok(v) => Value::from(v),
                            Err(_) => Value::Null,
                        };
                        (vec![vec![value]], false)
                    };
                    Ok(ExecResult {
                        columns: vec!["count".to_string()],
                        rows,
                        truncated,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }
                "distinct" => {
                    let response = db.run_command(cmd).await.map_err(classify)?;
                    let values: Vec<Bson> =
                        response.get_array("values").cloned().unwrap_or_default();
                    let limit = query.row_limit as usize;
                    let truncated = values.len() > limit;
                    let rows: Vec<Vec<Value>> = values
                        .into_iter()
                        .take(limit)
                        .map(|b| vec![bson_to_json(b)])
                        .collect();
                    Ok(ExecResult {
                        columns: vec!["value".to_string()],
                        rows,
                        truncated,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }
                // Rejector already filters to find/aggregate/count/distinct.
                // This arm exists for type-system completeness — if the
                // rejector's allow-list and dispatch table drift, fail loudly.
                other => Err(ExecError::Forbidden(format!(
                    "command `{other}` is rejector-allowed but not dispatch-wired"
                ))),
            }
        }
        .await;
        // Command finished (success or typed error) — no orphaned operation
        // to kill. Guard stays armed ONLY if this future is dropped while
        // awaiting above (agent disconnect / outer `tokio::time::timeout`).
        kill_guard.disarm();
        result
    }
}

/// Pluck the wire-order first key (the command name) out of an already-
/// parsed `Document`. Mongo's wire convention is "first key is the
/// command name" — bson 3's `Document` preserves insertion order so
/// `keys().next()` returns it.
fn first_command_name(doc: &Document) -> Option<String> {
    doc.keys().next().map(|k| k.to_string())
}

/// Convert a `bson::Document` to a `serde_json::Value` using mongo's
/// relaxed extended JSON format. Plain scalars / arrays / docs map 1:1;
/// mongo-specific types (`ObjectId`, `Date`, `Decimal128`) render as the
/// standard `{ "$oid": ... }` / `{ "$date": ... }` shapes operators
/// expect — same rendering `mongosh` produces. Falls back to `Value::Null`
/// if serialization fails (should be impossible for a `Document` we just
/// received from the driver).
fn doc_to_json(doc: Document) -> Value {
    bson_to_json(Bson::Document(doc))
}

fn bson_to_json(b: Bson) -> Value {
    // bson 3 routes through serde. The default Serialize impl produces the
    // relaxed extended JSON shape (`ObjectId` → `{ "$oid": "..." }`, etc.)
    // which matches what `mongosh` prints — operators reading the audit
    // row or the tool response see the same renderings they'd see at the
    // shell, with no ad-hoc translation in between.
    serde_json::to_value(&b).unwrap_or(Value::Null)
}

/// Map a `mongodb::error::Error` to our typed `ExecError`. The mapping
/// preserves the same semantics as `pg::classify`:
///
/// - `maxTimeMS` exhaustion → `Timeout`. Mongo's wire-protocol code is
///   `50` (`MaxTimeMSExpired`), surfaced via `ErrorKind::Command`.
/// - Connection / IO failures → `Unavailable`.
/// - Anything else (including a `Command` error for malformed BSON or a
///   non-existent collection) → `Sql`.
///
/// `Display` MUST NOT carry credentials. The driver's error renderings
/// don't include the connection URI in practice, but we map to typed
/// variants whose `Display` we control just in case.
fn classify(err: MongoError) -> ExecError {
    match err.kind.as_ref() {
        ErrorKind::Command(cmd_err) if cmd_err.code == 50 => ExecError::Timeout,
        ErrorKind::Io(_)
        | ErrorKind::ConnectionPoolCleared { .. }
        | ErrorKind::DnsResolve { .. }
        | ErrorKind::ServerSelection { .. } => ExecError::Unavailable,
        _ => ExecError::Sql,
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
            password: Password::Literal(password.into()),
            description: String::new(),
            auth_database: None,
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

    /// A command the rejector blocks must surface as
    /// [`ExecError::Forbidden`] (→ tool code `forbidden_sql`), not
    /// [`ExecError::Sql`] (→ `syntax_error`). The distinction matters per
    /// spec 03 — `syntax_error` is "DB rejected the SQL", whereas this is
    /// gateway-side policy denial. The carried message must include the
    /// reason so the tool layer can surface the operator-facing reason
    /// without leaking command values.
    #[tokio::test]
    async fn rejected_command_maps_to_forbidden_not_sql() {
        let s = server_for("localhost", 27017, Tls::Insecure);
        let d = database_for("app", "the_user", "pw");
        let adapter = MongoAdapter::open(&s, &d).await.expect("client constructs");

        // `$where` is a denied operator at any depth; the rejector returns
        // `DisallowedOperator("$where")`.
        let query = ExecQuery {
            sql: r#"{"find":"users","filter":{"$where":"true"}}"#,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 10,
        };
        let err = adapter
            .execute(query)
            .await
            .expect_err("denied command must error");
        match err {
            ExecError::Forbidden(reason) => assert!(
                reason.contains("$where"),
                "reason must name the denied operator, got: {reason}"
            ),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }
}
