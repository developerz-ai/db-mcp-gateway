//! The privilege queries `doctor` runs as a configured role. Every statement
//! is a catalog read inside a `READ ONLY` transaction that is rolled back.

use sqlx::{Connection, PgConnection, Row};

/// What one role can do on its database.
#[derive(Debug)]
pub struct Privileges {
    /// `rolsuper` / `rolbypassrls` / `rolcreaterole` / `rolcreatedb`, by name.
    pub role_attributes: Vec<&'static str>,
    pub default_read_only: bool,
    pub can_create_in_database: bool,
    /// Non-system schemas the role may `CREATE` in.
    pub create_schemas: Vec<String>,
    /// Relations the role may INSERT/UPDATE/DELETE/TRUNCATE (first 20).
    pub writable: Vec<String>,
    /// In-scope schemas the role has no `USAGE` on.
    pub schemas_without_usage: Vec<String>,
    /// In-scope relations the role cannot `SELECT` (first 50).
    pub unreadable: Vec<String>,
    pub max_connections: u32,
}

/// A `WHERE` fragment dropping the catalog, TOAST and temp schemas (a macro
/// so `concat!` keeps every statement a `&'static str`, which sqlx requires).
macro_rules! user_schemas {
    () => {
        "n.nspname NOT IN ('pg_catalog', 'information_schema') \
         AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp\\_%'"
    };
}

pub async fn privileges(
    conn: &mut PgConnection,
    schemas: &[String],
) -> Result<Privileges, sqlx::Error> {
    let mut tx = conn.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    let role = sqlx::query(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *tx)
    .await?;
    let role_attributes = ["rolsuper", "rolbypassrls", "rolcreaterole", "rolcreatedb"]
        .into_iter()
        .filter_map(|column| match role.try_get::<bool, _>(column) {
            Ok(true) => Some(Ok(column)),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<_, _>>()?;
    let default_read_only: String =
        sqlx::query_scalar("SELECT current_setting('default_transaction_read_only')")
            .fetch_one(&mut *tx)
            .await?;
    let can_create_in_database: bool =
        sqlx::query_scalar("SELECT has_database_privilege(current_database(), 'CREATE')")
            .fetch_one(&mut *tx)
            .await?;
    let create_schemas = names(
        &mut tx,
        concat!(
            "SELECT n.nspname FROM pg_namespace n WHERE ",
            user_schemas!(),
            " AND has_schema_privilege(n.oid, 'CREATE') ORDER BY 1"
        ),
        None,
    )
    .await?;
    let writable = names(
        &mut tx,
        concat!(
            "SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relkind IN ('r', 'p', 'v', 'f') AND ",
            user_schemas!(),
            " AND has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE') \
             ORDER BY 1 LIMIT 20"
        ),
        None,
    )
    .await?;
    let schemas_without_usage = names(
        &mut tx,
        "SELECT s FROM unnest($1::text[]) AS s \
         WHERE NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = s \
                           AND has_schema_privilege(n.oid, 'USAGE')) ORDER BY 1",
        Some(schemas),
    )
    .await?;
    let unreadable = names(
        &mut tx,
        "SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname = ANY($1) \
         AND NOT has_table_privilege(c.oid, 'SELECT') ORDER BY 1 LIMIT 50",
        Some(schemas),
    )
    .await?;
    let max_connections: String = sqlx::query_scalar("SELECT current_setting('max_connections')")
        .fetch_one(&mut *tx)
        .await?;
    tx.rollback().await?;
    let max_connections = max_connections
        .parse()
        .map_err(|err| sqlx::Error::Decode(Box::new(err)))?;
    Ok(Privileges {
        role_attributes,
        default_read_only: default_read_only == "on",
        can_create_in_database,
        create_schemas,
        writable,
        schemas_without_usage,
        unreadable,
        max_connections,
    })
}

async fn names(
    conn: &mut PgConnection,
    sql: &'static str,
    schemas: Option<&[String]>,
) -> Result<Vec<String>, sqlx::Error> {
    let query = sqlx::query_scalar::<_, String>(sql);
    let query = match schemas {
        Some(schemas) => query.bind(schemas),
        None => query,
    };
    query.fetch_all(conn).await
}
