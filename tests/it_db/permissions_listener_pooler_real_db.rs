//! The permissions listener behind a pooler (issue #407), against the real
//! state DB.
//!
//! pgcat in session mode relays a server's bytes only while it answers a
//! client's request, so a `NOTIFY` sits in the pooler until the listener's
//! connection asks for something. The relay here does the same. PgBouncer in
//! session mode relays at once and is the direct case.

use std::sync::atomic::Ordering;
use std::time::Duration;

use sqlx::postgres::PgSslMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::blackhole_proxy::Proxy;
use crate::common::env::state_pool;
use crate::permissions_listener_liveness_real_db::{
    HEARD_NO_PING, RECOVERED, capture_logs, cleanup, eventually, replica, revoke_and_notify, seed,
    state_options,
};
use db_mcp_gateway::state::permissions::pg::notify::Liveness;

const LIVENESS: Liveness = Liveness {
    ping_every: Duration::from_millis(250),
    deadline: Duration::from_secs(2),
};

/// Splits one direction of the plaintext protocol into message types.
struct Frames {
    pending: Vec<u8>,
    /// The client's first message has no type byte.
    startup: bool,
}

impl Frames {
    fn new(startup: bool) -> Self {
        Self {
            pending: Vec::new(),
            startup,
        }
    }

    /// Complete messages of one of `kinds` in what has arrived so far.
    fn count(&mut self, bytes: &[u8], kinds: &[u8]) -> usize {
        self.pending.extend_from_slice(bytes);
        let mut seen = 0;
        loop {
            let tag = usize::from(!self.startup);
            let Some(len) = self.pending.get(tag..tag + 4) else {
                return seen;
            };
            let end = tag + u32::from_be_bytes(len.try_into().unwrap()) as usize;
            if self.pending.len() < end {
                return seen;
            }
            seen += usize::from(!self.startup && kinds.contains(&self.pending[0]));
            self.startup = false;
            self.pending.drain(..end);
        }
    }
}

/// Relays to the client only while a request awaits its `ReadyForQuery`.
async fn relay_answers_only(mut client: TcpStream, upstream: (String, u16)) {
    let Ok(mut server) = TcpStream::connect(upstream).await else {
        return;
    };
    let (mut from_client, mut from_server) = ([0u8; 8192], [0u8; 8192]);
    let (mut requests, mut answers) = (Frames::new(true), Frames::new(false));
    // The startup message is answered by a `ReadyForQuery` too.
    let mut awaited = 1;
    loop {
        tokio::select! {
            read = client.read(&mut from_client) => {
                let Ok(n @ 1..) = read else { return };
                awaited += requests.count(&from_client[..n], b"QS");
                if server.write_all(&from_client[..n]).await.is_err() {
                    return;
                }
            }
            read = server.read(&mut from_server), if awaited > 0 => {
                let Ok(n @ 1..) = read else { return };
                awaited = awaited.saturating_sub(answers.count(&from_server[..n], b"Z"));
                if client.write_all(&from_server[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn answers_only_pooler(upstream: (String, u16)) -> u16 {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((client, _)) = socket.accept().await {
            tokio::spawn(relay_answers_only(client, upstream.clone()));
        }
    });
    port
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn revoke_is_heard_through_a_pooler_that_relays_only_answers() {
    let (logs, _guard) = capture_logs();
    let p = state_pool().await;
    let seeded = seed(&p, "pooler-answers").await;
    let direct = state_options();
    let port = answers_only_pooler((direct.get_host().to_string(), direct.get_port())).await;
    let via_pooler = direct
        .host("127.0.0.1")
        .port(port)
        .ssl_mode(PgSslMode::Disable);
    let b = replica(&p, via_pooler, LIVENESS);
    b.await_flushes(1).await;
    assert_eq!(b.grant_count(&seeded.sub).await, 1);

    // Well past the deadline: only pings heard through the pooler keep it up.
    tokio::time::sleep(LIVENESS.deadline * 3).await;
    assert_eq!(logs.count(HEARD_NO_PING), 0);

    revoke_and_notify(&p, &seeded).await;
    eventually("revoke reaches the replica", || async {
        b.grant_count(&seeded.sub).await == 0
    })
    .await;
    assert_eq!(
        b.flushes.load(Ordering::SeqCst),
        1,
        "the NOTIFY itself arrived; no reconnect flushed the cache"
    );

    b.listener.abort();
    cleanup(&p, &seeded).await;
}

/// A silently dead connection stays open until TCP gives up on it, minutes
/// later. However many pile up meanwhile, the replacement and its ping must
/// find a connection: one drop, one reconnect.
async fn each_silent_drop_costs_one_reconnect(drops: usize, freeze: impl Fn(&Proxy)) {
    let (logs, _guard) = capture_logs();
    let p = state_pool().await;
    let direct = state_options();
    let proxy = Proxy::start((direct.get_host().to_string(), direct.get_port())).await;
    let via_proxy = direct
        .host("127.0.0.1")
        .port(proxy.addr.port())
        .ssl_mode(PgSslMode::Disable);
    let b = replica(&p, via_proxy, LIVENESS);
    b.await_flushes(1).await;

    for drop in 1..=drops {
        freeze(&proxy);
        eventually("the listener recovers", || async {
            logs.count(RECOVERED) == drop
        })
        .await;
        tokio::time::sleep(LIVENESS.deadline * 2).await;
        assert_eq!(logs.count(HEARD_NO_PING), drop, "after drop {drop}");
    }

    b.listener.abort();
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn silent_drops_of_the_listen_connection_do_not_add_up() {
    each_silent_drop_costs_one_reconnect(3, |proxy| {
        proxy.freeze_listeners();
    })
    .await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn silent_drops_of_every_connection_do_not_add_up() {
    each_silent_drop_costs_one_reconnect(3, Proxy::freeze_all).await;
}
