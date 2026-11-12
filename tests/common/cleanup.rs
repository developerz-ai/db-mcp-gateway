//! State-DB row cleanup. Tests never TRUNCATE: they coexist with each other
//! and with dev rows, so each removes exactly what it created.

use sqlx::PgPool;
use uuid::Uuid;

/// Delete every `audit_calls` and `audit_call_intents` row for `user_sub`;
/// panics on failure.
pub async fn delete_audit_calls(pool: &PgPool, user_sub: &str) {
    for sql in [
        "DELETE FROM audit_call_intents WHERE user_sub = $1",
        "DELETE FROM audit_calls WHERE user_sub = $1",
    ] {
        sqlx::query(sql)
            .bind(user_sub)
            .execute(pool)
            .await
            .expect("cleanup audit rows");
    }
}

/// Best-effort: drop the `permissions_audit` rows about `target_id`.
pub async fn delete_permissions_audit(pool: &PgPool, target_id: Uuid) {
    let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(target_id)
        .execute(pool)
        .await;
}

/// Best-effort: drop the `permissions_users` row for `user_sub`.
pub async fn delete_permissions_user(pool: &PgPool, user_sub: &str) {
    let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(user_sub)
        .execute(pool)
        .await;
}

/// Best-effort: drop the `permissions_databases` row `id`.
pub async fn delete_permissions_database(pool: &PgPool, id: Uuid) {
    let _ = sqlx::query("DELETE FROM permissions_databases WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
}

/// Best-effort: drop the `permissions_grants` row `id`.
pub async fn delete_permissions_grant(pool: &PgPool, id: Uuid) {
    let _ = sqlx::query("DELETE FROM permissions_grants WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
}
