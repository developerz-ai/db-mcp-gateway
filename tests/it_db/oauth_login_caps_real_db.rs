//! The login stores' caps hold under concurrency, across replicas: inserts
//! racing for the last slot on separate connections admit exactly what the
//! cap leaves room for, and a restored code counts against it too.
//!
//! The global-cap tests are `#[serial_test::serial(world)]`: they size the cap
//! from the table's live count, and the consent one evicts others' rows.

use std::time::Duration;

use db_mcp_gateway::state::oauth::{self as db, ConsentCaps, NewAuthCode, NewConsent};
use futures::future::join_all;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::common::env::{state_db_url, state_pool};

const RACERS: usize = 16;

/// One connection per racer, so the inserts really run side by side.
async fn wide_pool() -> PgPool {
    state_pool().await;
    PgPoolOptions::new()
        .max_connections(RACERS as u32)
        .connect(&state_db_url())
        .await
        .expect("state DB up")
}

fn digest(raw: &str) -> Vec<u8> {
    Sha256::digest(raw.as_bytes()).to_vec()
}

async fn live_count(pool: &PgPool, table: &str) -> i64 {
    let sql = format!("SELECT count(*) FROM {table} WHERE expires_at > now()");
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(pool)
        .await
        .expect("count")
}

fn code<'a>(hash: &'a [u8], sub: &'a str, groups: &'a [String]) -> NewAuthCode<'a> {
    NewAuthCode {
        code_hash: hash,
        user_sub: sub,
        email: "caps@example.com",
        groups,
        code_challenge: "challenge",
        redirect_uri: "https://app.example/cb",
        client_id: "mcp-caps",
    }
}

async fn delete_codes(pool: &PgPool, sub: &str) {
    sqlx::query("DELETE FROM oauth_auth_codes WHERE user_sub = $1")
        .bind(sub)
        .execute(pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[serial_test::serial(world)]
async fn racing_code_inserts_fill_the_last_slot_once() {
    let pool = wide_pool().await;
    let sub = format!("caps-code-{}", Uuid::new_v4().simple());
    let groups: Vec<String> = Vec::new();
    let cap = live_count(&pool, "oauth_auth_codes").await + 1;
    let hashes: Vec<Vec<u8>> = (0..RACERS).map(|i| digest(&format!("{sub}-{i}"))).collect();

    let admitted = join_all(hashes.iter().map(|hash| {
        let pool = pool.clone();
        let row = code(hash, &sub, &groups);
        async move {
            db::insert_auth_code_capped(&pool, &row, chrono::Duration::seconds(60), cap)
                .await
                .expect("insert runs")
        }
    }))
    .await;

    assert_eq!(admitted.iter().filter(|ok| **ok).count(), 1, "{admitted:?}");

    // The store is full: a restore cannot push it past the cap either.
    let restored_hash = digest(&format!("{sub}-restored"));
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(60);
    let restored =
        db::restore_auth_code(&pool, &code(&restored_hash, &sub, &groups), expires_at, cap)
            .await
            .expect("restore runs");
    assert!(!restored, "a restore past the cap is refused");
    assert!(live_count(&pool, "oauth_auth_codes").await <= cap);

    delete_codes(&pool, &sub).await;
}

fn consent<'a>(hash: &'a [u8], sub: &'a str, bridge: &'a serde_json::Value) -> NewConsent<'a> {
    NewConsent {
        consent_hash: hash,
        csrf_hash: hash,
        user_sub: sub,
        email: "caps@example.com",
        groups: &[],
        bridge,
    }
}

async fn insert_consents(pool: &PgPool, sub: &str, labels: &[String], caps: ConsentCaps) {
    let bridge = serde_json::json!({});
    let hashes: Vec<Vec<u8>> = labels.iter().map(|label| digest(label)).collect();
    let results = join_all(hashes.iter().map(|hash| {
        let pool = pool.clone();
        let row = consent(hash, sub, &bridge);
        async move {
            let mut tx = pool.begin().await?;
            db::insert_consent(&mut tx, &row, chrono::Duration::seconds(300), caps).await?;
            tx.commit().await
        }
    }))
    .await;
    for result in results {
        result.expect("consent insert commits");
    }
}

async fn consents_of(pool: &PgPool, sub: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM oauth_pending_consents WHERE user_sub = $1")
        .bind(sub)
        .fetch_one(pool)
        .await
        .expect("count")
}

async fn delete_consents(pool: &PgPool, sub_prefix: &str) {
    sqlx::query("DELETE FROM oauth_pending_consents WHERE user_sub LIKE $1 || '%'")
        .bind(sub_prefix)
        .execute(pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn racing_consents_of_one_subject_stay_within_its_cap() {
    let pool = wide_pool().await;
    let sub = format!("caps-consent-{}", Uuid::new_v4().simple());
    let caps = ConsentCaps {
        per_subject: 5,
        total: 1_000_000,
    };
    let seeded: Vec<String> = (0..4).map(|i| format!("{sub}-seed-{i}")).collect();
    insert_consents(&pool, &sub, &seeded, caps).await;

    let racers: Vec<String> = (0..RACERS).map(|i| format!("{sub}-race-{i}")).collect();
    insert_consents(&pool, &sub, &racers, caps).await;

    assert_eq!(consents_of(&pool, &sub).await, 5);
    delete_consents(&pool, &sub).await;
}

#[tokio::test]
#[serial_test::serial(world)]
async fn racing_consents_stay_within_the_global_cap() {
    let pool = wide_pool().await;
    let prefix = format!("caps-global-{}", Uuid::new_v4().simple());
    let total = live_count(&pool, "oauth_pending_consents").await + 1;
    let caps = ConsentCaps {
        per_subject: 5,
        total,
    };

    let racers = (0..RACERS).map(|i| {
        let pool = pool.clone();
        let sub = format!("{prefix}-{i}");
        async move { insert_consents(&pool, &sub, std::slice::from_ref(&sub), caps).await }
    });
    tokio::time::timeout(Duration::from_secs(30), join_all(racers))
        .await
        .expect("inserts finish");

    assert!(live_count(&pool, "oauth_pending_consents").await <= total);
    delete_consents(&pool, &prefix).await;
}
