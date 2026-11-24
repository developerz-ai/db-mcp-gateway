//! `doctor` against the real target Postgres: a clean read role, then the
//! same role after it gains a write privilege and loses SELECT on a table,
//! then the superuser owner. Doctor only reads; every grant here is the
//! test's own fixture setup, run as the owner.

use std::process::Output;

use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

use crate::common::pg_target::{
    TARGET_DB, TARGET_HOST, TARGET_PASSWORD, TARGET_USER, owner_url, target_port,
};

const ROLE: &str = "dbmcp_doctor_ro";
const ROLE_PASSWORD: &str = "doctor-dev-only";

fn config(role: &str, password: &str) -> tempfile::NamedTempFile {
    let yaml = format!(
        "servers:\n  - name: target\n    kind: postgres\n    host: {TARGET_HOST}\n    \
         port: {}\n    tls: insecure\n    databases:\n      - {{ name: {TARGET_DB}, role: {role}, \
         password: \"{password}\" }}\npermissions: []\n",
        target_port()
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), yaml).unwrap();
    file
}

async fn doctor(config: &tempfile::NamedTempFile, schema: &str) -> (Option<i32>, String) {
    let path = config.path().display().to_string();
    let schema = schema.to_string();
    let output: Output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_db-mcp-gateway"))
            .args(["doctor", "--config", &path, "--schema", &schema])
            .env_clear()
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

async fn owner() -> PgConnection {
    PgConnection::connect(&owner_url()).await.unwrap()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn doctor_reports_privilege_drift_on_the_real_target() {
    let schema = format!("dbmcp_doctor_{}", Uuid::new_v4().simple());
    let mut owner = owner().await;
    for statement in [
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') \
             THEN CREATE ROLE {ROLE} LOGIN PASSWORD '{ROLE_PASSWORD}'; END IF; END $$"
        ),
        format!("GRANT CONNECT ON DATABASE {TARGET_DB} TO {ROLE}"),
        format!("CREATE SCHEMA {schema}"),
        format!("CREATE TABLE {schema}.orders (id int)"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {ROLE}"),
        format!("GRANT SELECT ON {schema}.orders TO {ROLE}"),
    ] {
        owner.execute(sqlx::AssertSqlSafe(statement)).await.unwrap();
    }
    let read_role = config(ROLE, ROLE_PASSWORD);

    let (code, out) = doctor(&read_role, &schema).await;
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("ok: no findings"), "{out}");
    assert!(out.contains("target max_connections = "), "{out}");
    assert!(!out.contains(ROLE_PASSWORD), "{out}");

    for statement in [
        format!("GRANT INSERT ON {schema}.orders TO {ROLE}"),
        format!("CREATE TABLE {schema}.secrets (id int)"),
    ] {
        owner.execute(sqlx::AssertSqlSafe(statement)).await.unwrap();
    }
    let (code, out) = doctor(&read_role, &schema).await;
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains(&format!("finding: read role can write: {schema}.orders")),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "finding: cannot SELECT in-scope relation(s): {schema}.secrets"
        )),
        "{out}"
    );

    // The dev owner is a superuser under a non-stock name: boot cannot see
    // that, doctor can.
    let (code, out) = doctor(&config(TARGET_USER, TARGET_PASSWORD), &schema).await;
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("finding: role has rolsuper"), "{out}");

    // Doctor changed nothing: the INSERT grant it reported is still there.
    let still: bool =
        sqlx::query_scalar("SELECT has_table_privilege($1, $2 || '.orders', 'INSERT')")
            .bind(ROLE)
            .bind(&schema)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert!(still);
    owner
        .execute(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .await
        .unwrap();
}

/// `has_table_privilege` ignores column grants; a read role that may
/// `UPDATE (col)` can still write. Serial: concurrent `GRANT CONNECT` on one
/// database races in the catalog ("tuple concurrently updated").
#[tokio::test]
#[serial_test::serial(world)]
async fn doctor_reports_a_column_only_write_grant() {
    let schema = format!("dbmcp_doctor_col_{}", Uuid::new_v4().simple());
    let mut owner = owner().await;
    for statement in [
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') \
             THEN CREATE ROLE {ROLE} LOGIN PASSWORD '{ROLE_PASSWORD}'; END IF; END $$"
        ),
        format!("GRANT CONNECT ON DATABASE {TARGET_DB} TO {ROLE}"),
        format!("CREATE SCHEMA {schema}"),
        format!("CREATE TABLE {schema}.notes (id int, body text)"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {ROLE}"),
        format!("GRANT SELECT ON {schema}.notes TO {ROLE}"),
        format!("GRANT UPDATE (body) ON {schema}.notes TO {ROLE}"),
    ] {
        owner.execute(sqlx::AssertSqlSafe(statement)).await.unwrap();
    }
    let (code, out) = doctor(&config(ROLE, ROLE_PASSWORD), &schema).await;
    owner
        .execute(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .await
        .unwrap();
    assert_eq!(code, Some(1), "{out}");
    // Other tests' fixtures may share the finding line; ours must be on it.
    assert!(
        out.lines().any(|line| line
            .trim_start()
            .starts_with("finding: read role can write: ")
            && line.contains(&format!("{schema}.notes"))),
        "{out}"
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn doctor_names_the_site_of_an_unresolved_secret() {
    let config = config(ROLE, "${ENV:DOCTOR_UNSET_PASSWORD}");
    let (code, out) = doctor(&config, "public").await;
    assert_eq!(code, Some(3), "{out}");
    assert!(
        out.contains("error: servers[target].databases[app].password (read tier)"),
        "{out}"
    );
}
