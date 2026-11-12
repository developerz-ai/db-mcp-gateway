use super::*;
use crate::audit::drain::DetachedTasks;
use crate::config::{Password, ServerKind};
use crate::exec::PoolSizing;

fn server_for(host: &str, port: u16, tls: Tls) -> Server {
    Server {
        name: "mongo".to_string(),
        kind: ServerKind::Mongo,
        description: String::new(),
        host: host.to_string(),
        port,
        tls,
        tls_ca_file: None,
        pool: None,
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
        pool: None,
    }
}

/// `MongoAdapter::Debug` must NEVER include the client (which renders
/// the parsed `ClientOptions` including credentials). Mirrors the
/// `PgAdapter` redaction test in `pg.rs`.
#[tokio::test]
async fn debug_does_not_leak_credentials() {
    let s = server_for("localhost", 27017, Tls::Required);
    let d = database_for("app", "the_user", "super_secret_pw");
    let adapter = MongoAdapter::open(&s, &d, PoolSizing::default(), DetachedTasks::new())
        .await
        .expect("client constructs");
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
    let adapter = MongoAdapter::open(&s, &d, PoolSizing::default(), DetachedTasks::new())
        .await
        .expect("client constructs");

    // `$where` is a denied operator at any depth; the rejector returns
    // `DisallowedOperator("$where")`.
    let query = ExecQuery {
        sql: r#"{"find":"users","filter":{"$where":"true"}}"#,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 10,
        access: crate::exec::Access::ReadOnly,
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

/// Catalog, sample and explain are SQL-shaped; until the mongo
/// implementations land they must fail with the typed "not implemented"
/// error (→ `internal`), never by handing SQL text to the driver.
#[tokio::test]
async fn sql_shaped_operations_are_not_implemented() {
    let s = server_for("localhost", 27017, Tls::Insecure);
    let d = database_for("app", "the_user", "pw");
    let adapter = MongoAdapter::open(&s, &d, PoolSizing::default(), DetachedTasks::new())
        .await
        .expect("client constructs");

    let schema = adapter
        .describe_schema(SchemaQuery {
            schema: "public",
            table: None,
            statement_timeout_ms: None,
            row_limit: 10,
        })
        .await;
    let ident = |s| crate::exec::Identifier::parse(s).expect("valid identifier");
    let sample = adapter
        .sample(SampleQuery {
            schema: ident("public"),
            table: ident("users"),
            statement_timeout_ms: None,
            row_limit: 10,
        })
        .await;
    let sql = crate::exec::sql_guard::ReadOnlySql::parse("SELECT 1").expect("read-only");
    let explain = adapter
        .explain(ExplainQuery {
            sql,
            statement_timeout_ms: None,
        })
        .await;

    for (result, want_op) in [
        (schema, "describe_schema"),
        (sample, "sample"),
        (explain, "explain"),
    ] {
        match result {
            Err(ExecError::NotImplemented {
                adapter: AdapterKind::Mongo,
                op,
            }) => assert_eq!(op, want_op),
            other => panic!("expected NotImplemented({want_op}), got {other:?}"),
        }
    }
}
