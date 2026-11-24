//! Mongo `describe_schema` `full` as a role that may list every collection
//! but read only some: the unreadable one is still listed, its sample
//! withheld, and the readable ones keep theirs — one denied `find` never
//! sinks the listing. Against `target-mongo`.
//!
//! Audit assertion intentionally skipped: this drives the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password};
use db_mcp_gateway::exec::{DbAdapter, MongoAdapter, PoolSizing, SchemaDetail, SchemaQuery};
use mongodb::bson::doc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::mongo_target::{database, server, side_client};

const PASSWORD: &str = "deny-dev-only";

/// A throwaway database holding `open` and `closed`, and a user of it whose
/// role lists both but may `find` in `open` only.
struct Fixture {
    database: String,
    user: String,
}

impl Fixture {
    async fn create() -> Self {
        let id = Uuid::new_v4().simple().to_string();
        let fixture = Self {
            database: format!("deny_{}", &id[..12]),
            user: format!("deny_{}", &id[..12]),
        };
        let db = side_client().database(&fixture.database);
        for collection in ["open", "closed"] {
            db.collection(collection)
                .insert_one(doc! { "field": 1 })
                .await
                .expect("seed");
        }
        db.run_command(doc! {
            "createRole": "lister",
            "privileges": [
                { "resource": { "db": &fixture.database, "collection": "" },
                  "actions": ["listCollections", "listIndexes"] },
                { "resource": { "db": &fixture.database, "collection": "open" },
                  "actions": ["find"] },
            ],
            "roles": [],
        })
        .await
        .expect("createRole");
        db.run_command(doc! {
            "createUser": &fixture.user, "pwd": PASSWORD, "roles": ["lister"],
        })
        .await
        .expect("createUser");
        fixture
    }

    async fn adapter(&self) -> MongoAdapter {
        let database = Database {
            name: self.database.clone(),
            role: self.user.clone(),
            password: Password::Literal(PASSWORD.into()),
            auth_database: Some(self.database.clone()),
            ..database()
        };
        let server = db_mcp_gateway::config::Server {
            databases: vec![database.clone()],
            ..server("mongo")
        };
        MongoAdapter::open(
            &server,
            &database,
            PoolSizing::default(),
            DetachedTasks::new(),
        )
        .await
        .expect("target-mongo reachable")
    }

    async fn drop(self) {
        let db = side_client().database(&self.database);
        for command in [
            doc! { "dropAllUsersFromDatabase": 1 },
            doc! { "dropAllRolesFromDatabase": 1 },
            doc! { "dropDatabase": 1 },
        ] {
            db.run_command(command).await.expect("fixture teardown");
        }
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_collection_the_role_cannot_read_is_listed_with_its_sample_withheld() {
    let fixture = Fixture::create().await;
    let adapter = fixture.adapter().await;
    let described = adapter
        .describe_schema(SchemaQuery {
            schema: None,
            table: None,
            search: None,
            detail: SchemaDetail::Full,
            statement_timeout_ms: None,
            row_limit: 100,
            sample_limit: 5,
            request_id: Uuid::new_v4(),
        })
        .await;
    fixture.drop().await;

    let described = described.expect("the listing answers");
    let sample = |name: &str| -> Value {
        described
            .rows
            .iter()
            .find(|row| row[1] == name)
            .map(|row| row[4].clone())
            .unwrap_or_else(|| panic!("{name} not listed: {:?}", described.rows))
    };
    assert_eq!(sample("open")["sampled"], 1, "{:?}", described.rows);
    assert_eq!(
        sample("closed"),
        json!({ "sampled": 0, "fields": [], "truncated": false,
                "withheld": "not readable by the database role" })
    );
}
