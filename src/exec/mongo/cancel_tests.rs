//! The cancel guard: marker, arming, redaction, and what it holds.

use std::sync::Arc;

use tokio::sync::Semaphore;

use super::*;

fn permits() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(1))
}

fn reservation(permits: &Arc<Semaphore>) -> Reservation {
    Reservation {
        _connection: Arc::clone(permits).try_acquire_owned().expect("a permit"),
        _slot: None,
    }
}

/// A client of a server that accepts and never answers.
async fn silent_client() -> Client {
    use mongodb::options::{ClientOptions, ServerAddress};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: "127.0.0.1".to_string(),
            port: Some(port),
        }])
        .build();
    Client::with_options(options).expect("client constructs")
}

/// Armed: the reservation lasts as long as the cancel, and no longer than
/// its bound. Disarmed: it ends with the guard.
#[tokio::test]
async fn the_cancel_holds_the_reservation_until_it_ends() {
    let client = silent_client().await;
    let permits = permits();
    let tasks = DetachedTasks::new();
    let mut done = KillOpOnDrop::armed(
        client.clone(),
        "done".to_string(),
        tasks.clone(),
        reservation(&permits),
    );
    done.disarm();
    drop(done);
    assert_eq!(permits.available_permits(), 1);

    let dropped = KillOpOnDrop::armed(
        client,
        "dropped".to_string(),
        tasks.clone(),
        reservation(&permits),
    );
    drop(dropped);
    assert_eq!(permits.available_permits(), 0);
    tasks
        .drain(CANCEL_BOUND + Duration::from_secs(1))
        .await
        .expect("a stuck cancel is bounded");
    assert_eq!(permits.available_permits(), 1);
}

#[test]
fn stamp_marker_inserts_comment_and_returns_it() {
    let mut cmd = doc! { "find": "users" };
    let marker = stamp_marker(&mut cmd);
    assert_eq!(cmd.get_str("comment").unwrap(), marker);
    // Sanity: markers are actually unique, not a constant placeholder.
    let mut cmd2 = doc! { "find": "users" };
    let marker2 = stamp_marker(&mut cmd2);
    assert_ne!(marker, marker2);
}

/// A caller-supplied `comment` must never survive the stamp — otherwise
/// it could collide with (or be crafted to match) another request's
/// marker and confuse the currentOp lookup.
#[test]
fn stamp_marker_overwrites_existing_comment() {
    let mut cmd = doc! { "find": "users", "comment": "caller-supplied" };
    let marker = stamp_marker(&mut cmd);
    assert_eq!(cmd.get_str("comment").unwrap(), marker);
    assert_ne!(marker, "caller-supplied");
}

/// `disarm()` must prevent the detached spawn on drop. `Client::with_options`
/// never opens a connection until first use (same posture as `mod.rs`'s
/// own tests), so this is safe to construct without a real mongo
/// instance — the assertion is just that `armed` is `None` after
/// `disarm()`, which is what `Drop::drop` checks before spawning.
#[tokio::test]
async fn disarm_prevents_drop_from_spawning() {
    use mongodb::options::{ClientOptions, ServerAddress};

    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: "localhost".to_string(),
            port: Some(27017),
        }])
        .build();
    let client = Client::with_options(options).expect("client constructs");

    let mut guard = KillOpOnDrop::armed(
        client,
        "unused-marker".to_string(),
        DetachedTasks::new(),
        reservation(&permits()),
    );
    assert!(guard.armed.is_some());
    guard.disarm();
    assert!(guard.armed.is_none());
    // Drop now runs with `armed == None` — `Drop::drop`'s `let Some(...)
    // = ... else { return }` returns immediately, no spawn.
}

/// `Debug` must never leak the mongo client (credentials in
/// `ClientOptions`) or the request-scoped marker. Mirrors
/// `MongoAdapter::debug_does_not_leak_credentials`.
#[tokio::test]
async fn debug_does_not_leak_client_or_marker() {
    use mongodb::options::{ClientOptions, ServerAddress};

    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: "leak-host".to_string(),
            port: Some(27017),
        }])
        .build();
    let client = Client::with_options(options).expect("client constructs");
    let marker = "leak-marker-should-not-appear";
    let guard = KillOpOnDrop::armed(
        client,
        marker.to_string(),
        DetachedTasks::new(),
        reservation(&permits()),
    );
    let rendered = format!("{guard:?}");
    assert!(rendered.contains("armed"));
    assert!(!rendered.contains(marker), "leaked marker: {rendered}");
    assert!(!rendered.contains("leak-host"), "leaked host: {rendered}");
}
