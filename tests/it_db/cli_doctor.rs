//! `doctor` against the real target Postgres: a clean read role, then the
//! same role after it gains a write privilege and loses SELECT on a table,
//! then the superuser owner. Doctor only reads; every grant here is the
//! test's own fixture setup, run as the owner.

use std::process::Output;
use std::sync::{Arc, Mutex};

use sqlx::{Connection, Executor, PgConnection};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::common::pg_target::{
    TARGET_DB, TARGET_HOST, TARGET_PASSWORD, TARGET_USER, owner_url, target_port,
};

const ROLE: &str = "dbmcp_doctor_ro";
const ROLE_PASSWORD: &str = "doctor-dev-only";

fn config(role: &str, password: &str) -> tempfile::NamedTempFile {
    let name = format!("name: {TARGET_DB}");
    config_at(TARGET_HOST, target_port(), &name, role, password)
}

/// `names`: the database's `name:`, and its `connect_name:` if it has one.
fn config_at(
    host: &str,
    port: u16,
    names: &str,
    role: &str,
    password: &str,
) -> tempfile::NamedTempFile {
    let yaml = format!(
        "servers:\n  - name: target\n    kind: postgres\n    host: {host}\n    \
         port: {port}\n    tls: insecure\n    databases:\n      - {{ {names}, role: {role}, \
         password: \"{password}\" }}\npermissions: []\n"
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

/// A TCP forwarder to the target, keeping what its one client sent.
async fn recorder() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let sent: Arc<Mutex<Vec<u8>>> = Arc::default();
    let record = sent.clone();
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let target = TcpStream::connect((TARGET_HOST, target_port()))
            .await
            .unwrap();
        let (from_client, mut to_client) = client.into_split();
        let (mut from_target, mut to_target) = target.into_split();
        tokio::spawn(async move { tokio::io::copy(&mut from_target, &mut to_client).await });
        let mut chunk = [0u8; 8192];
        loop {
            from_client.readable().await.unwrap();
            match from_client.try_read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => {
                    record.lock().unwrap().extend_from_slice(&chunk[..n]);
                    to_target.write_all(&chunk[..n]).await.unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    });
    (port, sent)
}

/// The `(kind, body)` of each client message after the untyped startup one.
fn messages(mut wire: &[u8]) -> Vec<(u8, String)> {
    let len = |at: &[u8]| u32::from_be_bytes(at[..4].try_into().unwrap()) as usize;
    wire = &wire[len(wire)..];
    let mut messages = Vec::new();
    while let Some((kind, rest)) = wire.split_first() {
        let (message, next) = rest.split_at(len(rest));
        messages.push((*kind, String::from_utf8_lossy(&message[4..]).into_owned()));
        wire = next;
    }
    messages
}

/// A transaction-mode pooler serves only unnamed statements, and those only
/// inside a transaction (as `pg_unnamed_statements_real_db` pins for targets).
#[tokio::test]
#[serial_test::parallel(world)]
async fn doctor_sends_unnamed_statements_inside_one_transaction() {
    let (port, sent) = recorder().await;
    let name = format!("name: {TARGET_DB}");
    let config = config_at("127.0.0.1", port, &name, TARGET_USER, TARGET_PASSWORD);

    let (code, out) = doctor(&config, "public").await;
    assert_eq!(code, Some(1), "the dev owner is a superuser: {out}");

    let messages = messages(&sent.lock().unwrap());
    let at = |sql: &str| {
        messages
            .iter()
            .position(|(kind, text)| *kind == b'Q' && text.starts_with(sql))
            .unwrap_or_else(|| panic!("no {sql}"))
    };
    let (begin, rollback) = (at("BEGIN"), at("ROLLBACK"));
    let mut parsed = 0;
    for (i, (kind, text)) in messages.iter().enumerate() {
        // Parse starts with the statement's name; Bind with the portal's,
        // then the statement's.
        let name = match kind {
            b'P' => text.split('\0').next(),
            b'B' => text.split('\0').nth(1),
            _ => continue,
        };
        parsed += usize::from(*kind == b'P');
        assert_eq!(name, Some(""), "named statement: {text:?}");
        assert!(
            begin < i && i < rollback,
            "outside the transaction: {text:?}"
        );
    }
    assert!(parsed > 0, "the probe was recorded");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn doctor_connects_to_connect_name_and_reports_the_logical_name() {
    let names = format!("name: logical, connect_name: {TARGET_DB}");
    let port = target_port();
    let config = config_at(TARGET_HOST, port, &names, TARGET_USER, TARGET_PASSWORD);
    let (code, out) = doctor(&config, "public").await;
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("target/logical read role"), "{out}");
    assert!(out.contains("finding: role has rolsuper"), "{out}");
}
