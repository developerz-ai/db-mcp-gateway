//! The state-DB login stores (migration 0022) against real Postgres: rows hold
//! digests, never the bearer values or the IdP-side login secrets; every take
//! is single-use, also under concurrency and across store instances (two
//! replicas); lapsed rows read as absent and the GC sweeps only them; a
//! restored code keeps its deadline.
//!
//! The GC test is `#[serial_test::serial(world)]` (a table-wide sweep); the
//! rest touch only their own rows.

use db_mcp_gateway::auth::oauth::{AuthCodes, GrantIdentity, OAuthBridge, PendingFlows};
use secrecy::SecretSlice;
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::env::state_pool;

fn key() -> SecretSlice<u8> {
    b"shared-test-signing-key-32-bytes!".to_vec().into()
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn identity(sub: &str) -> GrantIdentity {
    GrantIdentity {
        sub: sub.into(),
        email: format!("{sub}@example.com"),
        groups: vec!["engineers".into()],
    }
}

fn bridge() -> OAuthBridge {
    OAuthBridge {
        client_id: "mcp-ha".into(),
        client_name: None,
        client_redirect_uri: "https://app.example/cb".into(),
        client_state: "client-state".into(),
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
        resource: None,
    }
}

async fn insert_code(codes: &AuthCodes, code: &str, sub: &str) {
    codes
        .insert(
            code,
            identity(sub),
            bridge().code_challenge,
            "https://app.example/cb".into(),
            "mcp-ha".into(),
        )
        .await
        .expect("code stored");
}

/// Expire the row keyed by `raw`'s digest in `table` (`column` is its key).
async fn expire(pool: &PgPool, table: &str, column: &str, raw: &str) {
    let sql = format!(
        "UPDATE {table} SET expires_at = now() - interval '1 second' \
         WHERE {column} = sha256(convert_to($1, 'UTF8'))"
    );
    let updated = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(raw)
        .execute(pool)
        .await
        .expect("expire row");
    assert_eq!(updated.rows_affected(), 1, "{table} row for the raw id");
}

/// Every column of every row in `table`, as text.
async fn table_text(pool: &PgPool, table: &str) -> String {
    let sql = format!("SELECT coalesce(string_agg(t::text, ' '), '') FROM {table} t");
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(pool)
        .await
        .expect("dump table")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn rows_hold_digests_never_the_raw_ids_or_login_secrets() {
    let pool = state_pool().await;
    let flows = PendingFlows::with_db(pool.clone(), &key());
    let (state, consent_id, csrf, code) = (
        unique("raw-state"),
        unique("raw-consent"),
        unique("raw-csrf"),
        unique("raw-code"),
    );
    let secrets = flows.login_secrets(&state);
    flows.insert_bridge(&state, bridge()).await.unwrap();
    let sub = unique("digest-user");
    flows
        .insert_consent(&consent_id, &csrf, identity(&sub), bridge())
        .await
        .unwrap();
    insert_code(&AuthCodes::with_db(pool.clone()), &code, &sub).await;

    let dump = [
        table_text(&pool, "oauth_pending_flows").await,
        table_text(&pool, "oauth_pending_consents").await,
        table_text(&pool, "oauth_auth_codes").await,
    ]
    .concat();
    for raw in [
        &state,
        &consent_id,
        &csrf,
        &code,
        &secrets.nonce,
        &secrets.idp_verifier,
    ] {
        assert!(!dump.contains(raw.as_str()), "`{raw}` stored in the clear");
    }
    let keyed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oauth_pending_flows \
         WHERE state_hash = sha256(convert_to($1, 'UTF8')))",
    )
    .bind(&state)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(keyed, "flow keyed by SHA-256(state)");
}

/// Two replicas are two store instances over one table: a login started on
/// one is finished on the other with the same derived secrets, once.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_flow_and_a_consent_cross_replicas_once() {
    let pool = state_pool().await;
    let (on_a, on_b) = (
        PendingFlows::with_db(pool.clone(), &key()),
        PendingFlows::with_db(pool.clone(), &key()),
    );
    let state = unique("state");
    let sent = on_a.login_secrets(&state);
    on_a.insert_bridge(&state, bridge()).await.unwrap();
    let flow = on_b.take(&state).await.unwrap().expect("live on B");
    assert_eq!(flow.nonce, sent.nonce);
    assert_eq!(flow.idp_verifier, sent.idp_verifier);
    let carried = flow.bridge.expect("bridge context");
    assert_eq!(carried.client_state, "client-state");
    assert!(on_a.take(&state).await.unwrap().is_none(), "single-use");

    let (consent_id, csrf) = (unique("consent"), unique("csrf"));
    on_b.insert_consent(&consent_id, &csrf, identity("u"), bridge())
        .await
        .unwrap();
    let consent = on_a.take_consent(&consent_id).await.unwrap().expect("live");
    assert!(consent.csrf_matches(&csrf));
    assert!(!consent.csrf_matches("forged"));
    assert!(on_b.take_consent(&consent_id).await.unwrap().is_none());

    // The bespoke `/auth/login` flow carries no bridge.
    let plain = unique("plain-state");
    on_a.insert(&plain).await.unwrap();
    let flow = on_b.take(&plain).await.unwrap().expect("live");
    assert!(flow.bridge.is_none());
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn concurrent_takes_of_one_code_have_exactly_one_winner() {
    let pool = state_pool().await;
    let code = unique("race-code");
    insert_code(&AuthCodes::with_db(pool.clone()), &code, "race-user").await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let takes: Vec<_> = (0..8)
        .map(|_| {
            let replica = AuthCodes::with_db(pool.clone());
            let code = code.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                replica.take(&code).await
            })
        })
        .collect();
    let mut winners = 0;
    for take in takes {
        if take.await.unwrap().expect("store up").is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn lapsed_rows_read_as_absent() {
    let pool = state_pool().await;
    let flows = PendingFlows::with_db(pool.clone(), &key());
    let codes = AuthCodes::with_db(pool.clone());
    let (state, consent_id, code) = (unique("state"), unique("consent"), unique("code"));
    flows.insert(&state).await.unwrap();
    flows
        .insert_consent(&consent_id, "csrf", identity("u"), bridge())
        .await
        .unwrap();
    insert_code(&codes, &code, "lapsed-user").await;
    expire(&pool, "oauth_pending_flows", "state_hash", &state).await;
    expire(&pool, "oauth_pending_consents", "consent_hash", &consent_id).await;
    expire(&pool, "oauth_auth_codes", "code_hash", &code).await;

    assert!(flows.take(&state).await.unwrap().is_none());
    assert!(flows.take_consent(&consent_id).await.unwrap().is_none());
    assert!(codes.take(&code).await.unwrap().is_none());
    assert!(codes.take(&unique("never-issued")).await.unwrap().is_none());
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_restored_code_keeps_its_deadline() {
    let pool = state_pool().await;
    let codes = AuthCodes::with_db(pool.clone());
    let code = unique("restore-code");
    insert_code(&codes, &code, "restore-user").await;
    let deadline = || async {
        sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT expires_at FROM oauth_auth_codes \
             WHERE code_hash = sha256(convert_to($1, 'UTF8'))",
        )
        .bind(&code)
        .fetch_optional(&pool)
        .await
        .unwrap()
    };
    let before = deadline().await.expect("row");
    let entry = codes.take(&code).await.unwrap().expect("live");
    assert!(deadline().await.is_none(), "taken means deleted");
    codes.restore(&code, entry).await.unwrap();
    assert_eq!(deadline().await, Some(before));
    assert!(codes.take(&code).await.unwrap().is_some());
}

#[tokio::test]
#[serial_test::serial(world)]
async fn gc_sweeps_only_lapsed_login_state() {
    let pool = state_pool().await;
    let flows = PendingFlows::with_db(pool.clone(), &key());
    let codes = AuthCodes::with_db(pool.clone());
    let (stale_state, live_state) = (unique("stale"), unique("live"));
    let (stale_consent, stale_code, live_code) =
        (unique("stale-c"), unique("stale-code"), unique("live-code"));
    flows.insert(&stale_state).await.unwrap();
    flows.insert(&live_state).await.unwrap();
    flows
        .insert_consent(&stale_consent, "csrf", identity("gc"), bridge())
        .await
        .unwrap();
    insert_code(&codes, &stale_code, "gc").await;
    insert_code(&codes, &live_code, "gc").await;
    expire(&pool, "oauth_pending_flows", "state_hash", &stale_state).await;
    expire(
        &pool,
        "oauth_pending_consents",
        "consent_hash",
        &stale_consent,
    )
    .await;
    expire(&pool, "oauth_auth_codes", "code_hash", &stale_code).await;

    assert!(
        flows.gc_expired().await >= 2,
        "stale flow and consent swept"
    );
    assert!(codes.gc_expired().await >= 1, "stale code swept");
    let lapsed: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM oauth_pending_flows WHERE expires_at <= now()) \
              + (SELECT count(*) FROM oauth_pending_consents WHERE expires_at <= now()) \
              + (SELECT count(*) FROM oauth_auth_codes WHERE expires_at <= now())",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lapsed, 0);
    assert!(flows.take(&live_state).await.unwrap().is_some());
    assert!(codes.take(&live_code).await.unwrap().is_some());
}
